# Python GUI 编程（六）

> 原文：[`zh.annas-archive.org/md5/9d5f7126bd532a80dd6a9dce44175aaa`](https://zh.annas-archive.org/md5/9d5f7126bd532a80dd6a9dce44175aaa)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十五章：理解 OOP 概念

在本章中，我们将涵盖以下主题：

+   面向对象编程

+   在 GUI 中使用类

+   使用单一继承

+   使用多层继承

+   使用多重继承

# 面向对象编程

Python 支持**面向对象编程**（**OOP**）。OOP 支持可重用性；也就是说，之前编写的代码可以被重用来制作大型应用程序，而不是从头开始。OOP 中的对象指的是类的变量或实例，其中类是一个结构的模板或蓝图，包括方法和变量。类中的变量称为**数据成员**，方法称为**成员函数**。当类的实例或对象被创建时，对象会自动获得对数据成员和方法的访问。

# 创建一个类

`class`语句用于创建一个类。以下是创建类的语法：

```py
class class_name(base_classes):
    statement(s)
```

这里，`class_name`是一个标识符，用于标识类。在`class`语句之后是构成类主体的语句。`class`主体包括要在该类中定义的不同方法和变量。

您可以创建一个独立的类或继承另一个类。被继承的类称为**基类**。在语法中，`class_name`后的`base_classes`参数表示该类将继承的所有基类。如果有多个基类，则它们需要用逗号分隔。被继承的类称为**超类**或**基类**，继承的类称为**派生类**或**子类**。派生类可以使用基类的方法和变量，从而实现可重用性：

```py
class Student:
    name = ""
    def __init__(self, name):
        self.name = name
    def printName(self):
        return self.name
```

在此示例中，`Student`是一个包含名为`name`的属性的类，该属性初始化为 null。

# 使用内置类属性

`class`语句会自动为某些固定的类属性分配特定的值。这些类属性可以用于获取有关类的信息。类属性的列表如下：

+   `__name__`：表示`class`语句中使用的类名

+   `__bases__`：表示`class`语句中提到的基类名称

+   `__dict__`：表示其他类属性的字典对象

+   `__module__`：表示定义类的模块名称

一个类可以有任意数量的方法，每个方法可以有任意数量的参数。方法中始终定义了一个强制的第一个参数，通常将该第一个参数命名为`self`（尽管您可以为此参数指定任何名称）。`self`参数指的是调用方法的类的实例。在类中定义方法的语法如下：

```py
class class_name(base_classes):
    Syntax:
        variable(s)
    def method 1(self):
        statement(s)
    [def method n(self):
        statement(s)]
```

一个类可以有以下两种类型的数据成员：

+   **类变量**：这些是所有实例可共享的变量，任何一个实例对这些变量所做的更改也可以被其他实例看到。这些是在类的任何方法之外定义的数据成员。

+   **实例变量**：这些变量仅在方法内部定义，仅属于对象的当前实例，并且被称为**实例变量**。任何实例对实例变量所做的更改仅限于该特定实例，并不影响其他实例的实例变量。

让我们看看如何创建一个实例方法以及如何使用它来访问类变量。

# 在实例方法中访问类变量

要访问类变量，必须使用类名作为前缀。例如，要访问`Student`类的`name`类变量，需要按以下方式访问：

```py
Student.name
```

您可以看到，`name`类变量以`Student`类名作为前缀。

# 实例

要使用任何类的变量和方法，我们需要创建其对象或实例。类的实例会得到自己的变量和方法的副本。这意味着一个实例的变量不会干扰另一个实例的变量。我们可以创建任意数量的类的实例。要创建类的实例，需要写类名，后跟参数（如果有）。例如，以下语句创建了一个名为`studentObj`的`Student`类的实例：

```py
studentObj=Student()
```

可以创建任意数量的`Student`类的实例。例如，以下行创建了`Student`类的另一个实例：

```py
courseStudent=Student()
```

现在，实例可以访问类的属性和方法。

在定义方法时需要明确指定`self`。在调用方法时，`self`不是必需的，因为 Python 会自动添加它。

要定义类的变量，我们需要使用`__init__()`方法的帮助。`__init__()`方法类似于传统面向对象编程语言中的构造函数，并且是在创建实例后首先执行的方法。它用于初始化类的变量。根据类中如何定义`__init__()`方法，即是否带有参数，参数可能会传递给`__init__()`方法，也可能不会。

如前所述，每个类方法的第一个参数是一个称为`self`的类实例。在`__init__()`方法中，`self`指的是新创建的实例：

```py
class Student:
    name = ""
    def __init__(self):
        self.name = "David"
        studentObj=Student()
```

在上面的例子中，`studentObj`实例是正在创建的`Student`类的实例，并且其类变量将被初始化为`David`字符串。

甚至可以将参数传递给`__init__()`方法，如下例所示：

```py
class Student:
    name = ""
    def __init__(self, name):
        self.name = name
        studentObj=Student("David")
```

在上面的例子中，创建了`studentObj`实例并将`David`字符串传递给它。该字符串将被分配给`__init__()`方法中定义的`name`参数，然后用于初始化实例的类变量`name`。请记住，`__init__()`方法不能返回值。

与类变量一样，可以通过类的实例访问类的方法，后跟方法名，中间用句点(`.`)分隔。假设`Student`类中有一个`printName()`方法，可以通过以下语句通过`studentObj`实例访问：

```py
studentObj.printName()
```

# 在 GUI 中使用类

通过 GUI 从用户接收的数据可以直接通过简单变量进行处理，并且处理后的数据只能通过变量显示。但是，为了保持数据的结构化格式并获得面向对象编程的好处，我们将学习将数据保存在类的形式中。也就是说，用户通过 GUI 访问的数据可以分配给类变量，通过类方法进行处理和显示。

让我们创建一个应用程序，提示用户输入姓名，并在输入姓名后点击推送按钮时，应用程序将显示一个 hello 消息以及输入的姓名。用户输入的姓名将被分配给一个类变量，并且 hello 消息也将通过调用类的类方法生成。

# 如何做...

本节的重点是理解用户输入的数据如何分配给类变量，以及如何通过类方法访问显示的消息。让我们基于没有按钮的对话框模板创建一个新应用程序，并按照以下步骤进行操作：

1.  将两个标签小部件、一个行编辑和一个推送按钮小部件拖放到表单上。

1.  将第一个标签小部件的文本属性设置为`输入您的姓名`。

让我们不要更改第二个标签小部件的文本属性，并将其文本属性保持为默认值`TextLabel`。这是因为它的文本属性将通过代码设置以显示 hello 消息。

1.  将推送按钮小部件的文本属性设置为`Click`。

1.  将 LineEdit 小部件的 objectName 属性设置为`lineEditName`。

1.  将 Label 小部件的 objectName 属性设置为`labelResponse`。

1.  将 Push Button 小部件的 objectName 属性设置为`ButtonClickMe`。

1.  将应用程序保存为名称为`LineEditClass.ui`的应用程序。应用程序将显示如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/8899b4c1-7dfa-4483-8ceb-5e17f7e60834.png)

使用 Qt Designer 创建的用户界面存储在`.ui`文件中，这是一个 XML 文件，需要转换为 Python 代码。

1.  要进行转换，您需要打开命令提示符窗口，导航到保存文件的文件夹，并发出以下命令行：

```py
C:\Pythonbook\PyQt5>pyuic5 LineEdit.uiClass -o LineEditClass.py
```

可以在本书的源代码包中看到生成的 Python 脚本`LineEditClass.py`。

1.  将上述代码视为头文件，并将其导入到将调用其用户界面设计的文件中。

1.  创建另一个名为`callLineEditClass.pyw`的 Python 文件，并将`LineEditClass.py`代码导入其中：

```py
import sys
from PyQt5.QtWidgets import QDialog, QApplication
from LineEditClass import *
class Student:
    name = ""
    def __init__(self, name):
        self.name = name
    def printName(self):
        return self.name
class MyForm(QDialog):
    def __init__(self):
        super().__init__()
        self.ui = Ui_Dialog()
        self.ui.setupUi(self)
        self.ui.ButtonClickMe.clicked.connect(self.dispmessage)
        self.show()
    def dispmessage(self):
        studentObj=Student(self.ui.lineEditName.text())
        self.ui.labelResponse.setText("Hello 
        "+studentObj.printName())
if __name__=="__main__":
    app = QApplication(sys.argv)
    w = MyForm()
    w.show()
    sys.exit(app.exec_())
```

# 它是如何工作的...

在`LineEditClass.py`文件中，创建了一个名为顶级对象的类，其名称为`Ui_ prepended`。也就是说，对于顶级对象`Dialog`，创建了`Ui_Dialog`类，并存储了小部件的接口元素。该类有两个方法，`setupUi()`和`retranslateUi()`。`setupUi()`方法创建了在 Qt Designer 中定义用户界面时使用的小部件。此方法还设置了小部件的属性。`setupUi()`方法接受一个参数，即应用程序的顶级小部件，即`QDialog`的实例。`retranslateUi()`方法翻译了界面。

在`callLineEditClass.py`文件中，可以看到定义了一个名为`Student`的类。`Student`类包括一个名为`name`的类变量和以下两个方法：

+   `__init__()`: 这是一个构造函数，它接受强制的`self`参数和一个`name`参数，该参数将用于初始化`name`类变量

+   `printName`: 此方法简单地返回名称类变量中的值

将 Push Button 小部件的`clicked()`事件连接到`dispmessage()`方法；在 LineEdit 小部件中输入名称后，当用户单击按钮时，将调用`dispmessage()`方法。`dispmessage()`方法通过名称定义了`Student`类的对象，`studentObj`，并将用户在 LineEdit 小部件中输入的名称作为参数传递。因此，将调用`Student`类的构造函数，并将用户输入的名称传递给构造函数。在 LineEdit 小部件中输入的名称将被分配给类变量`name`。之后，名为`labelResponse`的 Label 小部件将设置为显示字符串`Hello`，并调用`Student`类的`printName`方法，该方法返回分配给名称变量的字符串。

因此，单击按钮后，Label 小部件将设置为显示字符串`Hello`，然后是用户在 LineEdit 框中输入的名称，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/4087bf43-9f4a-438f-9afc-3896bed1d43a.png)

# 使应用程序更加详细

我们还可以在类中使用两个或更多类属性。

假设除了类名`Student`之外，我们还想将学生的代码添加到类中。在这种情况下，我们需要向类中添加一个名为`code`的属性，还需要一个`getCode()`方法，该方法将访问分配的学生代码。除了类之外，GUI 也将发生变化。

我们需要向应用程序添加一个以上的 Label 小部件和一个 LineEdit 小部件，并将其保存为另一个名称`demoStudentClass`。添加 Label 和 LineEdit 小部件后，用户界面将显示如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/a7049b4f-3d2b-444c-9acd-db786bb48423.png)

用户界面文件`demoStudentClass.ui`需要转换为 Python 代码。可以在本书的源代码包中看到生成的 Python 脚本`demoStudentClass.py`。

让我们创建另一个名为`callStudentClass.pyw`的 Python 文件，并将`demoStudentClass.py`代码导入其中。`callStudentClass.pyw`中的代码如下：

```py
import sys
from PyQt5.QtWidgets import QDialog, QApplication
from demoStudentClass import *
class Student:
    name = ""
    code = ""
    def __init__(self, code, name):
        self.code = code
        self.name = name
    def getCode(self):
        return self.code
    def getName(self):
        return self.name
class MyForm(QDialog):
    def __init__(self):
        super().__init__()
        self.ui = Ui_Dialog()
        self.ui.setupUi(self)
        self.ui.ButtonClickMe.clicked.connect(self.dispmessage)
        self.show()
    def dispmessage(self):
        studentObj=Student(self.ui.lineEditCode.text(),             
        self.ui.lineEditName.text())
        self.ui.labelResponse.setText("Code: 
        "+studentObj.getCode()+", Name:"+studentObj.getName())
if __name__=="__main__":
    app = QApplication(sys.argv)
    w = MyForm()
    w.show()
    sys.exit(app.exec_())
```

在上述代码中，您可以看到定义了一个名为`Student`的类。`Student`类包括两个名为`name`和`code`的类变量。除了这两个类变量，`Student`类还包括以下三个方法：

+   `__init__()`: 这是一个构造函数，它接受强制的`self`参数和两个参数，`code`和`name`，它们将用于初始化两个类变量，`code`和`name`

+   `getCode()`: 该方法简单地返回`code`类变量中的值

+   `getName()`: 该方法简单地返回`name`类变量中的值

推按钮小部件的`clicked()`事件连接到`dispmessage()`方法；在行编辑小部件中输入代码和名称后，用户单击推按钮，将调用`dispmessage()`方法。`dispmessage()`方法通过名称定义`Student`类的对象，`studentObj`，并将用户在行编辑小部件中输入的代码和名称作为参数传递。`Student`类的构造函数`__init__()`将被调用，并将用户输入的代码和名称传递给它。输入的代码和名称将分别分配给类变量 code 和 name。之后，标签小部件称为`labelResponse`被设置为通过`Student`类的`studentObj`对象调用两个方法`getCode`和`getName`显示输入的代码和名称。

因此，单击推按钮后，标签小部件将显示用户在两个行编辑小部件中输入的代码和名称，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/e9877017-e033-432c-a3c9-fd5b0d47c65f.png)

# 继承

继承是一个概念，通过该概念，现有类的方法和变量可以被另一个类重用，而无需重新编写它们。也就是说，经过测试和运行的现有代码可以立即在其他类中重用。

# 继承的类型

以下是三种继承类型：

+   **单一继承**: 一个类继承另一个类

+   **多级继承**: 一个类继承另一个类，而后者又被另一个类继承

+   **多重继承**: 一个类继承两个或更多个类

# 使用单一继承

单一继承是最简单的继承类型，其中一个类从另一个单一类派生，如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/a30a06b6-5b72-4811-863e-2597433190bf.png)

类**B**继承类**A**。在这里，类**A**将被称为超类或基类，类**B**将被称为派生类或子类。

以下语句定义了单一继承，其中`Marks`类继承了`Student`类：

```py
class Marks(Student):
```

在上述语句中，`Student`是基类，`Marks`是派生类。因此，`Marks`类的实例可以访问`Student`类的方法和变量。

# 准备就绪

为了通过一个运行示例理解单一继承的概念，让我们创建一个应用程序，提示用户输入学生的代码、名称、历史和地理成绩，并在单击按钮时显示它们。

用户输入的代码和名称将被分配给名为`Student`的类的类成员。历史和地理成绩将被分配给名为`Marks`的另一个类的类成员。

为了访问代码和名称，以及历史和地理成绩，`Marks`类将继承`Student`类。使用继承，`Marks`类的实例将访问并显示`Student`类的代码和名称。

# 如何做...

启动 Qt Designer，并根据以下步骤创建一个基于无按钮对话框模板的新应用程序：

1.  在应用程序中，将五个标签小部件、四个行编辑小部件和一个按钮小部件拖放到表单上。

1.  将四个标签小部件的文本属性设置为`学生代码`，`学生姓名`，`历史成绩`和`地理成绩`。

1.  删除第五个标签小部件的文本属性，因为它的文本属性将通过代码设置以显示代码、名称、历史和地理成绩。

1.  将按钮小部件的文本属性设置为`点击`。

1.  将四个行编辑小部件的 objectName 属性设置为`lineEditCode`，`lineEditName`，`lineEditHistoryMarks`和`lineEditGeographyMarks`。

1.  将标签小部件的 objectName 属性设置为`labelResponse`，将按钮小部件的 objectName 属性设置为`ButtonClickMe`。

1.  使用名称`demoSimpleInheritance.ui`保存应用程序。应用程序将显示如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/ae5f11dc-7444-41b8-bbb6-8ee75483b7ac.png)

用户界面文件`demoSimpleInheritance.ui`是一个 XML 文件，并使用`pyuic5`实用程序转换为 Python 代码。您可以在本书的源代码包中找到生成的 Python 脚本`demoSimpleInheritance.py`。上述代码将被用作头文件，并将被导入到另一个 Python 脚本文件中，该文件将调用在`demoSimpleInheritance.py`文件中定义的用户界面设计。

1.  创建另一个名为`callSimpleInheritance.pyw`的 Python 文件，并将`demoSimpleInheritance.py`代码导入其中。Python 脚本`callSimpleInheritance.pyw`中的代码如下所示：

```py
import sys
from PyQt5.QtWidgets import QDialog, QApplication
from demoSimpleInheritance import *
class Student:
    name = ""
    code = ""
    def __init__(self, code, name):
        self.code = code
        self.name = name
    def getCode(self):
        return self.code
    def getName(self):
        return self.name
class Marks(Student):
    historyMarks = 0
    geographyMarks = 0
    def __init__(self, code, name, historyMarks, 
    geographyMarks):
        Student.__init__(self,code,name)
        self.historyMarks = historyMarks
        self.geographyMarks = geographyMarks
    def getHistoryMarks(self):
        return self.historyMarks
    def getGeographyMarks(self):
        return self.geographyMarks
class MyForm(QDialog):
    def __init__(self):
        super().__init__()
        self.ui = Ui_Dialog()
        self.ui.setupUi(self)
        self.ui.ButtonClickMe.clicked.connect(self.dispmessage)
        self.show()
    def dispmessage(self):
        marksObj=Marks(self.ui.lineEditCode.text(),                           
        self.ui.lineEditName.text(), 
        self.ui.lineEditHistoryMarks.text(),     
        self.ui.lineEditGeographyMarks.text())
        self.ui.labelResponse.setText("Code:     
        "+marksObj.getCode()+", Name:"+marksObj.getName()+"
        nHistory Marks:"+marksObj.getHistoryMarks()+", Geography         
        Marks:"+marksObj.getGeographyMarks())
if __name__=="__main__":
    app = QApplication(sys.argv)
    w = MyForm()
    w.show()
    sys.exit(app.exec_())
```

# 它是如何工作的...

在这段代码中，您可以看到定义了一个名为`Student`的类。`Student`类包括两个名为`name`和`code`的类变量，以及以下三个方法：

+   `__init__()`: 这是一个构造函数，它接受强制的`self`参数和两个参数，`code`和`name`，这些参数将用于初始化两个类变量，`code`和`name`

+   `getCode()`: 这个方法简单地返回`code`类变量中的值

+   `getName()`: 这个方法简单地返回`name`类变量中的值

`Marks`类继承了`Student`类。因此，`Marks`类的实例不仅能够访问自己的成员，还能够访问`Student`类的成员。

`Marks`类包括两个名为`historyMarks`和`geographyMarks`的类变量，以及以下三个方法：

+   `__init__()`: 这是一个构造函数，它接受强制的`self`参数和四个参数，`code`，`name`，`historyMarks`和`geographyMarks`。从这个构造函数中，将调用`Student`类的构造函数，并将`code`和`name`参数传递给这个构造函数。`historyMarks`和`geographyMarks`参数将用于初始化类成员`historyMarks`和`geographyMarks`。

+   `getHistoryMarks()`: 这个方法简单地返回`historyMarks`类变量中的值。

+   `getGeographyMarks()`: 这个方法简单地返回`geographyMarks`类变量中的值。

按钮的`clicked()`事件连接到`dispmessage()`方法。在 Line Edit 小部件中输入代码、姓名、历史和地理成绩后，用户单击按钮时，将调用`dispmessage()`方法。`dispmessage()`方法通过名称定义了`Marks`类的对象`marksObj`，并将用户在 Line Edit 小部件中输入的代码、姓名、历史和地理成绩作为参数传递。`Marks`类的构造函数`__init__()`将被调用，并将用户输入的代码、姓名、历史和地理成绩传递给它。从`Marks`类的构造函数中，将调用`Student`类的构造函数，并将`code`和`name`传递给该构造函数。`code`和`name`参数将分别分配给`Student`类的`code`和`name`类变量。

类似地，历史和地理成绩将分配给`Marks`类的`historyMarks`和`geographyMarks`类变量。之后，将设置名为`labelResponse`的 Label 小部件，以通过调用四个方法`getCode`、`getName`、`getHistoryMarks`和`getGeographyMarks`来显示用户输入的代码、姓名、历史和地理成绩。通过`marksObj`对象，`Marks`类的`marksObj`对象获得了访问`Student`类的`getCode`和`getName`方法的权限，因为使用了继承。

因此，单击按钮后，Label 小部件将通过名为`labelResponse`的 Label 小部件显示用户输入的代码、姓名、历史成绩和地理成绩，如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/85fd758c-d18c-4054-82f6-e71290dc9ff3.png)

# 使用多级继承

多级继承是指一个类继承另一个单一类。转而继承第三个类，如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/60be84f7-6eaa-49f2-b0bb-7f9adc6f8627.png)

在上图中，您可以看到类**B**继承了类**A**，而类**C**又继承了类**B**。

以下语句定义了多级继承，其中`Result`类继承了`Marks`类，而`Marks`类又继承了`Student`类：

```py
class Student:
    class Marks(Student):
        class Result(Marks):
```

在上述语句中，`Student`是基类，`Marks`类继承了`Student`类。`Result`类继承了`Marks`类。因此，`Result`类的实例可以访问`Marks`类的方法和变量，而`Marks`类的实例可以访问`Student`类的方法和变量。

# 准备就绪

为了理解多级继承的概念，让我们创建一个应用程序，提示用户输入学生的代码、姓名、历史成绩和地理成绩，并在单击按钮时显示总分和百分比。总分将是历史成绩和地理成绩的总和。假设最高分为 100，计算百分比的公式为：总分/200 * 100。

用户输入的代码和姓名将分配给名为`Student`的类的类成员。历史和地理成绩将分配给名为`Marks`的另一个类的类成员。

为了访问代码和姓名以及历史和地理成绩，`Marks`类将继承`Student`类。

使用这种多层继承，`Marks`类的实例将访问`Student`类的代码和名称。为了计算总分和百分比，还使用了一个名为`Result`的类。`Result`类将继承`Marks`类。因此，`Result`类的实例可以访问`Marks`类的类成员，以及`Student`类的成员。`Result`类有两个类成员，`totalMarks`和`percentage`。`totalMarks`类成员将被分配为`Marks`类的`historyMarks`和`geographyMarks`成员的总和。百分比成员将根据历史和地理成绩获得的百分比进行分配。

# 如何做到...

总之，有三个类，名为`Student`，`Marks`和`Result`，其中`Result`类将继承`Marks`类，而`Marks`类将继承`Student`类。因此，`Result`类的成员可以访问`Marks`类的类成员以及`Student`类的成员。以下是创建此应用程序的逐步过程：

1.  启动 Qt Designer 并基于无按钮模板创建一个新应用程序。

1.  将六个 Label 小部件、六个 Line Edit 小部件和一个 Push Button 小部件拖放到表单上。

1.  将六个 Label 小部件的文本属性设置为`Student Code`、`Student Name`、`History Marks`、`Geography Marks`、`Total`和`Percentage`。

1.  将 Push Button 小部件的文本属性设置为`Click`。

1.  将六个 Line Edit 小部件的对象名称属性设置为`lineEditCode`、`lineEditName`、`lineEditHistoryMarks`、`lineEditGeographyMarks`、`lineEditTotal`和`lineEditPercentage`。

1.  将 Push Button 小部件的对象名称属性设置为`ButtonClickMe`。

1.  通过取消选中属性编辑器窗口中的启用属性，禁用`lineEditTotal`和`lineEditPercentage`框。`lineEditTotal`和`lineEditPercentage`小部件被禁用，因为这些框中的值将通过代码分配，我们不希望用户更改它们的值。

1.  使用名称`demoMultilevelInheritance.ui`保存应用程序。应用程序将显示如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/6e59be73-0f7c-455e-a947-bfb9c7883a3a.png)

用户界面文件`demoMultilevelInheritance.ui`是一个 XML 文件，并通过使用`pyuic5`实用程序将其转换为 Python 代码。您可以在本书的源代码包中看到生成的 Python 脚本`demoMultilevelInheritance.py`。`demoMultilevelInheritance.py`文件将用作头文件，并将在另一个 Python 脚本文件中导入，该文件将使用在`demoMultilevelInheritance.py`中创建的 GUI。

1.  创建另一个名为`callMultilevelInheritance.pyw`的 Python 文件，并将`demoMultilevelInheritance.py`代码导入其中。Python 脚本`callMultilevelInheritance.pyw`中的代码如下所示：

```py
import sys
from PyQt5.QtWidgets import QDialog, QApplication
from demoMultilevelInheritance import *
class Student:
    name = ""
    code = ""
    def __init__(self, code, name):
        self.code = code
        self.name = name
    def getCode(self):
        return self.code
    def getName(self):
        return self.name
class Marks(Student):
    historyMarks = 0
    geographyMarks = 0
    def __init__(self, code, name, historyMarks, 
    geographyMarks):
        Student.__init__(self,code,name)
        self.historyMarks = historyMarks
        self.geographyMarks = geographyMarks
    def getHistoryMarks(self):
        return self.historyMarks
    def getGeographyMarks(self):
        return self.geographyMarks
class Result(Marks):
    totalMarks = 0
    percentage = 0
    def __init__(self, code, name, historyMarks, 
    geographyMarks):
        Marks.__init__(self, code, name, historyMarks, 
        geographyMarks)
        self.totalMarks = historyMarks + geographyMarks
        self.percentage = (historyMarks + 
        geographyMarks) / 200 * 100
    def getTotalMarks(self):
        return self.totalMarks
    def getPercentage(self):
        return self.percentage
class MyForm(QDialog):
    def __init__(self):
        super().__init__()
        self.ui = Ui_Dialog()
        self.ui.setupUi(self)
        self.ui.ButtonClickMe.clicked.connect(self.dispmessage)
        self.show()
    def dispmessage(self):
        resultObj=Result(self.ui.lineEditCode.text(),                      
        self.ui.lineEditName.text(),           
        int(self.ui.lineEditHistoryMarks.text()),      
        int(self.ui.lineEditGeographyMarks.text()))
        self.ui.lineEditTotal.setText(str(resultObj.
        getTotalMarks()))
        self.ui.lineEditPercentage.setText(str(resultObj.
        getPercentage()))
if __name__=="__main__":
    app = QApplication(sys.argv)
    w = MyForm()
    w.show()
    sys.exit(app.exec_())
```

# 工作原理...

在上述代码中，在`callMultilevelInheritance.pyw`文件中，您可以看到定义了一个名为`Student`的类。`Student`类包括两个名为`name`和`code`的类变量，以及以下三种方法：

+   `__init__()`: 这是一个构造函数，它接受强制的`self`参数和两个参数，`code`和`name`，用于初始化两个类变量`code`和`name`

+   `getCode()`: 此方法简单地返回`code`类变量中的值

+   `getName()`: 此方法简单地返回`name`类变量中的值

`Marks`类继承`Student`类。因此，`Marks`类的实例不仅能够访问自己的成员，还能够访问`Student`类的成员。

`Marks`类包括两个名为`historyMarks`和`geographyMarks`的类变量，以及以下三种方法：

+   `__init__()`: 这是一个构造函数，它接受强制的`self`参数和四个参数，`code`、`name`、`historyMarks`和`geographyMarks`。从这个构造函数中，将调用`Student`类的构造函数，并将`code`和`name`参数传递给该构造函数。`historyMarks`和`geographyMarks`参数将用于初始化`historyMarks`和`geographyMarks`类成员。

+   `getHistoryMarks()`: 此方法简单地返回`historyMarks`类变量中的值。

+   `getGeographyMarks()`: 此方法简单地返回`geographyMarks`类变量中的值。

`Result`类继承了`Marks`类。`Result`类的实例不仅能够访问自己的成员，还能访问`Marks`类和`Student`类的成员。

`Result`类包括两个类变量，称为`totalMarks`和`percentage`，以及以下三个方法：

+   `__init__()`: 这是一个构造函数，它接受强制的`self`参数和四个参数，`code`、`name`、`historyMarks`和`geographyMarks`。从这个构造函数中，将调用`Marks`类的构造函数，并将`code`、`name`、`historyMarks`和`geographyMarks`参数传递给该构造函数。`historyMarks`和`geographyMarks`的总和将被赋给`totalMarks`类变量。假设每个的最高分为 100，将计算历史和地理成绩的百分比，并将其分配给百分比类变量。

+   `getTotalMarks()`: 此方法简单地返回`historyMarks`和`geographyMarks`类变量的总和。

+   `getPercentage()`: 此方法简单地返回历史和地理成绩的百分比。

按钮小部件的`clicked()`事件连接到`dispmessage()`方法。在行编辑小部件中输入代码、姓名、历史成绩和地理成绩后，用户单击按钮，将调用`dispmessage()`方法。`dispmessage()`方法通过姓名`resultObj`定义`Result`类的对象，并将用户在行编辑小部件中输入的代码、姓名、历史和地理成绩作为参数传递。`Result`类的构造函数`__init__()`将被调用，并将用户输入的代码、姓名、历史成绩和地理成绩传递给它。从`Result`类的构造函数中，将调用`Marks`类的构造函数，并将代码、姓名、历史成绩和地理成绩传递给该构造函数。从`Marks`类的构造函数中，将调用`Student`类的构造函数，并将`code`和`name`参数传递给它。在`Student`类的构造函数中，`code`和`name`参数将分配给类变量`code`和`name`。类似地，历史和地理成绩将分配给`Marks`类的`historyMarks`和`geographyMarks`类变量。

`historyMarks`和`geographyMarks`的总和将被赋给`totalMarks`类变量。此外，历史和地理成绩的百分比将被计算并赋给`percentage`类变量。

之后，称为`lineEditTotal`的行编辑小部件被设置为通过`resultObj`调用`getTotalMarks`方法来显示总分，即历史和地理成绩的总和。同样，称为`lineEditPercentage`的行编辑小部件被设置为通过`resultObj`调用`getPercentage`方法来显示百分比。

因此，单击按钮后，称为`lineEditTotal`和`lineEditPercentage`的行编辑小部件将显示用户输入的历史和地理成绩的总分和百分比，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/d449d2e5-b4df-4d4b-83de-7453ccab8863.png)

# 使用多重继承

多重继承是指一个类继承了两个或更多个类，如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/18fd865e-1ed7-4668-8579-ecb61a333042.png)

类**C**同时继承类**A**和类**B**。

以下语句定义了多级继承，其中`Result`类继承了`Marks`类，而`Marks`类又继承了`Student`类：

```py
class Student:
    class Marks:
        class Result(Student, Marks):
```

在前面的语句中，`Student`和`Marks`是基类，`Result`类继承了`Student`类和`Marks`类。因此，`Result`类的实例可以访问`Marks`和`Student`类的方法和变量。

# 准备就绪

为了实际理解多级继承的概念，让我们创建一个应用程序，提示用户输入学生的代码、姓名、历史成绩和地理成绩，并在单击按钮时显示总分和百分比。总分将是历史成绩和地理成绩的总和。假设每个的最高分为 100，计算百分比的公式为：总分/200 * 100。

用户输入的代码和姓名将分配给一个名为`Student`的类的类成员。历史和地理成绩将分配给另一个名为`Marks`的类的类成员。

为了访问代码和姓名，以及历史和地理成绩，`Result`类将同时继承`Student`类和`Marks`类。使用这种多重继承，`Result`类的实例可以访问`Student`类的代码和姓名，以及`Marks`类的`historyMarks`和`geographyMarks`类变量。换句话说，使用多重继承，`Result`类的实例可以访问`Marks`类的类成员，以及`Student`类的类成员。`Result`类有两个类成员，`totalMarks`和`percentage`。`totalMarks`类成员将被分配为`Marks`类的`historyMarks`和`geographyMarks`成员的总和。百分比成员将根据历史和地理成绩的基础上获得的百分比进行分配。

# 如何做...

让我们通过逐步过程来了解多级继承如何应用于三个类，`Student`，`Marks`和`Result`。`Result`类将同时继承`Student`和`Marks`两个类。这些步骤解释了`Result`类的成员如何通过多级继承访问`Student`和`Marks`类的类成员：

1.  启动 Qt Designer，并基于无按钮的对话框模板创建一个新应用程序。

1.  在应用程序中，将六个标签小部件、六个行编辑小部件和一个按钮小部件拖放到表单上。

1.  将六个标签小部件的文本属性设置为`学生代码`，`学生姓名`，`历史成绩`，`地理成绩`，`总分`和`百分比`。

1.  将按钮小部件的文本属性设置为`点击`。

1.  将六个行编辑小部件的 objectName 属性设置为`lineEditCode`，`lineEditName`，`lineEditHistoryMarks`，`lineEditGeographyMarks`，`lineEditTotal`和`lineEditPercentage`。

1.  将按钮小部件的 objectName 属性设置为`ButtonClickMe`。

1.  通过取消选中属性编辑器窗口中的启用属性，禁用`lineEditTotal`和`lineEditPercentage`框。`lineEditTotal`和`lineEditPercentage`框被禁用，因为这些框中的值将通过代码分配，并且我们不希望用户更改它们的值。

1.  使用名称`demoMultipleInheritance.ui`保存应用程序。应用程序将显示如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/a27d6894-3d5e-4a3d-a2af-f12757b4dc3e.png)

用户界面文件`demoMultipleInheritance .ui`是一个 XML 文件，并使用`pyuic5`实用程序转换为 Python 代码。您可以在本书的源代码包中找到生成的 Python 代码`demoMultipleInheritance.py`。`demoMultipleInheritance.py`文件将被用作头文件，并将在另一个 Python 脚本文件中导入，该文件将调用在`demoMultipleInheritance.py`文件中创建的 GUI。

1.  创建另一个名为`callMultipleInheritance.pyw`的 Python 文件，并将`demoMultipleInheritance.py`代码导入其中：

```py
import sys
from PyQt5.QtWidgets import QDialog, QApplication
from demoMultipleInheritance import *
class Student:
    name = ""
    code = ""
    def __init__(self, code, name):
        self.code = code
        self.name = name
    def getCode(self):
        return self.code
    def getName(self):
        return self.name
class Marks:
    historyMarks = 0
    geographyMarks = 0
    def __init__(self, historyMarks, geographyMarks):
        self.historyMarks = historyMarks
        self.geographyMarks = geographyMarks
    def getHistoryMarks(self):
        return self.historyMarks
    def getGeographyMarks(self):
        return self.geographyMarks
class Result(Student, Marks):
    totalMarks = 0
    percentage = 0
    def __init__(self, code, name, historyMarks, 
    geographyMarks):
        Student.__init__(self, code, name)
        Marks.__init__(self, historyMarks, geographyMarks)
        self.totalMarks = historyMarks + geographyMarks
        self.percentage = (historyMarks + 
        geographyMarks) / 200 * 100
    def getTotalMarks(self):
        return self.totalMarks
    def getPercentage(self):
        return self.percentage
class MyForm(QDialog):
    def __init__(self):
        super().__init__()
        self.ui = Ui_Dialog()
        self.ui.setupUi(self)
        self.ui.ButtonClickMe.clicked.connect(self.dispmessage)
        self.show()
    def dispmessage(self):
        resultObj=Result(self.ui.lineEditCode.text(),         
        self.ui.lineEditName.text(),
        int(self.ui.lineEditHistoryMarks.text()),  
        int(self.ui.lineEditGeographyMarks.text()))
        self.ui.lineEditTotal.setText(str(resultObj.
        getTotalMarks()))
        self.ui.lineEditPercentage.setText(str(resultObj.
        getPercentage()))
if __name__=="__main__":
    app = QApplication(sys.argv)
    w = MyForm()
    w.show()
    sys.exit(app.exec_())
```

# 工作原理...

在这段代码中，您可以看到定义了一个名为`Student`的类。`Student`类包括两个名为`name`和`code`的类变量，以及以下三种方法：

+   `__init__()`: 这是一个构造函数，它接受强制的`self`参数和两个参数，`code`和`name`，这些参数将用于初始化两个类变量`code`和`name`。

+   `getCode()`: 此方法简单地返回`code`类变量中的值

+   `getName()`: 此方法简单地返回`name`类变量中的值

`Marks`类包括两个类变量，名为`historyMarks`和`geographyMarks`，以及以下三种方法：

+   `__init__()`: 这是一个构造函数，它接受强制的`self`参数和两个参数，`historyMarks`和`geographyMarks`。`historyMarks`和`geographyMarks`参数将用于初始化`historyMarks`和`geographyMarks`类成员。

+   `getHistoryMarks()`: 此方法简单地返回`historyMarks`类变量中的值。

+   `getGeographyMarks()`: 此方法简单地返回`geographyMarks`类变量中的值。

`Result`类继承了`Student`类以及`Marks`类。`Result`类的实例不仅能够访问自己的成员，还能够访问`Marks`类和`Student`类的成员。

`Result`类包括两个名为`totalMarks`和`percentage`的类变量，以及以下三种方法：

+   `__init__()`: 这是一个构造函数，它接受强制的`self`参数和四个参数，`code`、`name`、`historyMarks`和`geographyMarks`。从这个构造函数中，将调用`Student`类的构造函数，并将`code`和`name`参数传递给该构造函数。同样，从这个构造函数中，将调用`Marks`类的构造函数，并将`historyMarks`和`geographyMarks`参数传递给该构造函数。`historyMarks`和`geographyMarks`的总和将被分配给`totalMarks`类变量。假设每个的最高分数为 100，将计算历史和地理成绩的百分比，并将其分配给`percentage`类变量。

+   `getTotalMarks()`: 此方法简单地返回`historyMarks`和`geography`类变量的总和。

+   `getPercentage()`: 此方法简单地返回历史和地理成绩的百分比。

按钮小部件的`clicked()`事件连接到`dispmessage()`方法。在 LineEdit 小部件中输入代码、名称、历史成绩和地理成绩后，当用户单击按钮时，将调用`dispmessage()`方法。`dispmessage()`方法通过名称定义了`Result`类的对象，`resultObj`，并将用户在 LineEdit 小部件中输入的代码、名称、历史成绩和地理成绩作为参数传递。将调用`Result`类的构造函数`__init__()`，并将用户输入的代码、名称、历史成绩和地理成绩传递给它。从`Result`类的构造函数中，将调用`Student`类的构造函数和`Marks`类的构造函数。代码和名称将传递给`Student`类的构造函数，历史和地理成绩将传递给`Marks`类的构造函数。

在`Student`类构造函数中，代码和名称将分配给`code`和`name`类变量。同样，在`Marks`类构造函数中，历史和地理成绩将分配给`Marks`类的`historyMarks`和`geographyMarks`类变量。

`historyMarks`和`geographyMarks`的总和将分配给`totalMarks`类变量。此外，历史和地理成绩的百分比将计算并分配给`percentage`类变量。

之后，LineEdit 小部件称为`lineEditTotal`被设置为通过`resultObj`调用`getTotalMarks`方法来显示总分，即历史和地理成绩的总和。同样，LineEdit 小部件称为`lineEditPercentage`被设置为通过`resultObj`调用`getPercentage`方法来显示百分比。

因此，单击按钮后，LineEdit 小部件称为`lineEditTotal`和`lineEditPercentage`将显示用户输入的历史和地理成绩的总分和百分比，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/e3d7ca1c-8089-43bc-b7ee-b4391dce7d38.png)


# 第十六章：理解对话框

在本章中，我们将学习如何使用以下类型的对话框：

+   输入对话框

+   使用输入对话框

+   使用颜色对话框

+   使用字体对话框

+   使用文件对话框

# 介绍

在所有应用程序中都需要对话框来从用户那里获取输入，还要指导用户输入正确的数据。交互式对话框也使应用程序变得非常用户友好。基本上有以下两种类型的对话框：

+   **模态对话框**：模态对话框是一种要求用户输入强制信息的对话框。这种对话框在关闭之前不允许用户使用应用程序的其他部分。也就是说，用户需要在模态对话框中输入所需的信息，关闭对话框后，用户才能访问应用程序的其余部分。

+   **非模态或无模式对话框**：这些对话框使用户能够与应用程序的其余部分和对话框进行交互。也就是说，用户可以在保持无模式对话框打开的同时继续与应用程序的其余部分进行交互。这就是为什么无模式对话框通常用于从用户那里获取非必要或非关键信息。

# 输入对话框

使用`QInputDialog`类来创建输入对话框。`QInputDialog`类提供了一个对话框，用于从用户那里获取单个值。提供的输入对话框包括一个文本字段和两个按钮，OK 和 Cancel。文本字段使我们能够从用户那里获取单个值，该单个值可以是字符串、数字或列表中的项目。以下是`QInputDialog`类提供的方法，用于接受用户不同类型的输入：

+   `getInt()`:该方法显示一个旋转框以接受整数。要从用户那里得到一个整数，您需要使用以下语法：

```py
getInt(self, window title, label before LineEdit widget, default value, minimum, maximum and step size)
```

看一下下面的例子：

```py
quantity, ok = QInputDialog.getInt(self, "Order Quantity", "Enter quantity:", 2, 1, 100, 1)
```

前面的代码提示用户输入数量。如果用户没有输入任何值，则默认值`2`将被赋给`quantity`变量。用户可以输入`1`到`100`之间的任何值。

+   `getDouble()`:该方法显示一个带有浮点数的旋转框，以接受小数值。要从用户那里得到一个小数值，您需要使用以下语法：

```py
getDouble(self, window title, label before LineEdit widget, default value, minimum, maximum and number of decimal places desired)
```

看一下下面的例子：

```py
price, ok = QInputDialog.getDouble(self, "Price of the product", "Enter price:", 1.50,0, 100, 2)
```

前面的代码提示用户输入产品的价格。如果用户没有输入任何值，则默认值`1.50`将被赋给`price`变量。用户可以输入`0`到`100`之间的任何值。

+   `getText()`:该方法显示一个 Line Edit 小部件，以从用户那里接受文本。要从用户那里获取文本，您需要使用以下语法：

```py
getText(self, window title, label before LineEdit widget)
```

看一下下面的例子：

```py
name, ok = QtGui.QInputDialog.getText(self, 'Get Customer Name', 'Enter your name:')
```

前面的代码将显示一个标题为“获取客户名称”的输入对话框。对话框还将显示一个 Line Edit 小部件，允许用户输入一些文本。在 Line Edit 小部件之前还将显示一个 Label 小部件，显示文本“输入您的姓名:”。在对话框中输入的客户姓名将被赋给`name`变量。

+   `getItem()`:该方法显示一个下拉框，显示多个可供选择的项目。要从下拉框中获取项目，您需要使用以下语法：

```py
getItem(self, window title, label before combo box, array , current item, Boolean Editable)
```

这里，`array`是需要在下拉框中显示的项目列表。`current item`是在下拉框中被视为当前项目的项目。`Editable`是布尔值，如果设置为`True`，则意味着用户可以编辑下拉框并输入自己的文本。当`Editable`设置为`False`时，这意味着用户只能从下拉框中选择项目，但不能编辑项目。看一下下面的例子：

```py
countryName, ok = QInputDialog.getItem(self, "Input Dialog", "List of countries", countries, 0, False)
```

上述代码将显示一个标题为“输入对话框”的输入对话框。对话框显示一个下拉框，其中显示了通过 countries 数组的元素显示的国家列表。下拉框之前的 Label 小部件显示文本“国家列表”。从下拉框中选择的国家名称将被分配给`countryName`变量。用户只能从下拉框中选择国家，但不能编辑任何国家名称。

# 使用输入对话框

输入对话框可以接受任何类型的数据，包括整数、双精度和文本。在本示例中，我们将学习如何从用户那里获取文本。我们将利用输入对话框来了解用户所居住的国家的名称。

输入对话框将显示一个显示不同国家名称的下拉框。通过名称选择国家后，所选的国家名称将显示在文本框中。

# 如何做...

让我们根据没有按钮的对话框模板创建一个新的应用程序，执行以下步骤：

1.  由于应用程序将提示用户通过输入对话框选择所居住的国家，因此将一个 Label 小部件、一个 Line Edit 小部件和一个 Push Button 小部件拖放到表单中。

1.  将 Label 小部件的文本属性设置为“你的国家”。

1.  将 Push Button 小部件的文本属性设置为“选择国家”。

1.  将 Line Edit 小部件的 objectName 属性设置为`lineEditCountry`。

1.  将 Push Button 小部件的 objectName 属性设置为`pushButtonCountry`。

1.  将应用程序保存为`demoInputDialog.ui`。

现在表单将如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/3a59be73-9686-4b0a-92a6-c5ea8a7bf4b3.png)

使用 Qt Designer 创建的用户界面存储在`.ui`文件中，这是一个 XML 文件，需要转换为 Python 代码。

1.  要进行转换，您需要打开一个命令提示符窗口，导航到保存文件的文件夹，并发出以下命令行：

```py
C:\Pythonbook\PyQt5>pyuic5 demoInputDialog.ui -o demoInputDialog.py
```

您可以在本书的源代码包中找到生成的 Python 脚本`demoInputDialog.py`。

1.  将`demoInputDialog.py`脚本视为头文件，并将其导入到将调用其用户界面设计的文件中。

1.  创建另一个名为`callInputDialog.pyw`的 Python 文件，并将`demoInputDialog.py`的代码导入其中：

```py
import sys
from PyQt5.QtWidgets import QDialog, QApplication, QInputDialog
from demoInputDialog import *
class MyForm(QDialog):
    def __init__(self):
        super().__init__()
        self.ui = Ui_Dialog()
        self.ui.setupUi(self)
        self.ui.pushButtonCountry.clicked.connect(self.dispmessage)
        self.show()
    def dispmessage(self):
        countries = ("Albania", "Algeria", "Andorra", "Angola",   
        "Antigua and Barbuda", "Argentina", "Armenia", "Aruba", 
        "Australia", "Austria", "Azerbaijan")
        countryName, ok = QInputDialog.getItem(self, "Input  
        Dialog", "List of countries", countries, 0, False)
        if ok and countryName:
            self.ui.lineEditCountry.setText(countryName)
if __name__=="__main__":
    app = QApplication(sys.argv)
    w = MyForm()
    w.show()
    sys.exit(app.exec_())
```

# 工作原理...

在`demoInputDialog.py`文件中，创建一个名为顶层对象的类，前面加上`Ui_`。也就是说，对于顶层对象 Dialog，创建了`Ui_Dialog`类，并存储了我们小部件的接口元素。该类有两个方法，`setupUi()`和`retranslateUi()`。

`setupUi()`方法创建了在 Qt Designer 中定义用户界面中使用的小部件。此方法还设置了小部件的属性。`setupUi()`方法接受一个参数，即应用程序的顶层小部件，即`QDialog`的一个实例。`retranslateUi()`方法翻译了界面。

在`callInputDialog.pyw`文件中，可以看到 Push Button 小部件的单击事件连接到`dispmessage()`方法，该方法用于选择国家；当用户单击推送按钮时，将调用`dispmessage()`方法。`dispmessage()`方法定义了一个名为 countries 的字符串数组，其中包含了几个国家名称的数组元素。之后，调用`QInputDialog`类的`getItem`方法，打开一个显示下拉框的输入对话框。当用户单击下拉框时，它会展开，显示分配给`countries`字符串数组的国家名称。当用户选择一个国家，然后单击对话框中的 OK 按钮，所选的国家名称将被分配给`countryName`变量。然后，所选的国家名称将通过 Line Edit 小部件显示出来。

运行应用程序时，您将得到一个空的 Line Edit 小部件和一个名为“选择国家”的推送按钮，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/eb1fe98b-1676-4764-b7e0-ca45a599d5b5.png)

单击“选择国家”按钮后，输入对话框框将打开，如下截图所示。输入对话框显示一个组合框以及两个按钮“确定”和“取消”。单击组合框，它将展开显示所有国家名称，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/33a4befd-4197-4c3e-920c-fc7ce186433d.png)

从组合框中选择国家名称，然后单击“确定”按钮后，所选国家名称将显示在行编辑框中，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/362a4ebc-bc81-4595-826b-21c961807936.png)

# 使用颜色对话框

在本教程中，我们将学习使用颜色对话框显示颜色调色板，允许用户从调色板中选择预定义的颜色或创建新的自定义颜色。

该应用程序包括一个框架，当用户从颜色对话框中选择任何颜色时，所选颜色将应用于框架。除此之外，所选颜色的十六进制代码也将通过 Label 小部件显示。

在本教程中，我们将使用`QColorDialog`类，该类提供了一个用于选择颜色值的对话框小部件。

# 如何做到...

让我们根据以下步骤创建一个基于无按钮对话框模板的新应用程序：

1.  将一个 Push Button、一个 Frame 和一个 Label 小部件拖放到表单上。

1.  将 Push Button 小部件的文本属性设置为“选择颜色”。

1.  将 Push Button 小部件的 objectName 属性设置为`pushButtonColor`。

1.  将 Frame 小部件的 objectName 属性设置为`frameColor`。

1.  将 Label 小部件设置为`labelColor`。

1.  将应用程序保存为`demoColorDialog.ui`。

表格现在将如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/134219b5-01b1-4f44-bd45-52d5cdd09caa.png)

使用 Qt Designer 创建的用户界面存储在`.ui`文件中，这是一个 XML 文件。您可以使用`pyuic5`实用程序将 XML 文件转换为 Python 代码。生成的 Python 脚本`demoColorDialog.py`可以在本书的源代码包中找到。`demoColorDialog.py`脚本将用作头文件，并将在另一个 Python 脚本文件中导入，该文件将调用此用户界面设计。

1.  创建另一个名为`callColorDialog.pyw`的 Python 文件，并将`demoColorDialog.py`代码导入其中：

```py
import sys
from PyQt5.QtWidgets import QDialog, QApplication, QColorDialog
from PyQt5.QtGui import QColor
from demoColorDialog import *
class MyForm(QDialog):
    def __init__(self):
        super().__init__()
        col = QColor(0, 0, 0)
        self.ui = Ui_Dialog()
        self.ui.setupUi(self)
        self.ui.frameColor.setStyleSheet("QWidget { background-
        color: %s }" % col.name())
        self.ui.pushButtonColor.clicked.connect(self.dispcolor)
        self.show()
    def dispcolor(self):
        col = QColorDialog.getColor()
        if col.isValid():
        self.ui.frameColor.setStyleSheet("QWidget { background-  
        color: %s }" % col.name())
        self.ui.labelColor.setText("You have selected the color with 
        code: " + str(col.name()))
if __name__=="__main__":
    app = QApplication(sys.argv)
    w = MyForm()
    w.show()
    sys.exit(app.exec_())
```

# 它是如何工作的...

在`callColorDialog.pyw`文件中，您可以看到按钮的 click()事件连接到`dispcolor()`方法；也就是说，当用户单击“选择颜色”按钮时，将调用`dispcolor()`方法。`dispmessage()`方法调用`QColorDialog`类的`getColor()`方法，打开一个显示不同颜色的对话框。用户不仅可以从对话框中选择任何预定义的基本颜色，还可以创建新的自定义颜色。选择所需的颜色后，当用户从颜色对话框中单击“确定”按钮时，所选颜色将通过在 Frame 小部件类上调用`setStyleSheet()`方法来分配给框架。此外，所选颜色的十六进制代码也通过 Label 小部件显示。

运行应用程序时，最初会看到一个按钮“选择颜色”，以及一个默认填充为黑色的框架，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/49d02cee-9ab4-4642-8246-6ab2bd1c733b.png)

单击“选择颜色”按钮，颜色对话框将打开，显示以下截图中显示的基本颜色。颜色对话框还可以让您创建自定义颜色：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/b1c886f2-3210-4155-b51b-7083e10959cf.png)

选择颜色后，单击“确定”按钮，所选颜色将应用于框架，并且所选颜色的十六进制代码将通过 Label 小部件显示，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/594e7f78-ec74-4168-a3ac-caa5adae3102.png)

# 使用字体对话框

在本教程中，我们将学习使用字体对话框为所选文本应用不同的字体和样式。

在这个应用程序中，我们将使用 Text Edit 小部件和 Push Button 小部件。点击按钮后，将打开字体对话框。从字体对话框中选择的字体和样式将应用于 Text Edit 小部件中的文本。

在这个示例中，我们将使用`QFontDialog`类，该类显示一个用于选择字体的对话框小部件。

# 如何做...

让我们根据无按钮模板创建一个新的应用程序，执行以下步骤：

1.  将一个 Push Button 和一个 Text Edit 小部件拖放到表单上。

1.  将 Push Button 小部件的文本属性设置为`Choose Font`。

1.  将 Push Button 小部件的 objectName 属性设置为`pushButtonFont`。

1.  将应用程序保存为`demoFontDialog.ui`。

1.  执行上述步骤后，应用程序将显示如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/2c394b22-bf10-464e-828c-e79074e2cb4d.png)

使用 Qt Designer 创建的用户界面存储在`.ui`文件中，这是一个 XML 文件。使用`pyuic5`命令，您可以将 XML 文件转换为 Python 代码。生成的 Python 脚本`demoFontDialog.py`可以在本书的源代码包中找到。`demoFontDialog.py`脚本将被用作头文件，并将在另一个 Python 脚本文件中导入，该文件将调用此用户界面设计。

1.  创建另一个名为`callFontDialog.pyw`的 Python 文件，并将`demoFontDialog.py`代码导入其中。

```py
import sys
from PyQt5.QtWidgets import QDialog, QApplication, QFontDialog
from demoFontDialog import *
class MyForm(QDialog):
    def __init__(self):
        super().__init__()
        self.ui = Ui_Dialog()
        self.ui.setupUi(self)
        self.ui.pushButtonFont.clicked.connect(self.changefont)
        self.show()
    def changefont(self):
        font, ok = QFontDialog.getFont()
        if ok:
        self.ui.textEdit.setFont(font)
if __name__=="__main__":
    app = QApplication(sys.argv)
    w = MyForm()
    w.show()
    sys.exit(app.exec_())
```

# 工作原理...

在`callFontDialog.pyw`文件中，您可以看到将 push button 的 click()事件连接到`changefont()`方法；也就是说，当用户点击 Choose Font 按钮时，将调用`change()`方法。`changefont()`方法调用`QFontDialog`类的`getFont()`方法，打开一个对话框，显示不同的字体、字体样式、大小和效果。选择字体、字体样式、大小或效果后，将在示例框中显示文本的选择效果。选择所需的字体、字体样式、大小和效果后，当用户点击 OK 按钮时，所选的选择将被分配给`font`变量。随后，在`TextEdit`类上调用`setFont()`方法，将所选的字体和样式应用于通过 Text Edit 小部件显示的文本。

运行应用程序后，您将看到一个按钮，Change Font 小部件和 Text Edit 小部件，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/7cf1dce1-7e0a-4cfe-978e-601477340c7c.png)

要查看从字体对话框中选择的字体的影响，您需要在 Text Edit 小部件中输入一些文本，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/e93a5f1c-e881-4674-85ee-e3386739f82a.png)

选择 Change Font 按钮后，字体对话框将打开，如下截图所示。您可以看到不同的字体名称将显示在最左边的选项卡上。中间选项卡显示不同的字体样式，使您可以使文本以粗体、斜体、粗斜体和常规形式显示。最右边的选项卡显示不同的大小。在底部，您可以看到不同的复选框，使您可以使文本显示为下划线、删除线等。从任何选项卡中选择选项，所选字体和样式对示例框中显示的示例文本的影响可见。选择所需的字体和样式后，点击 OK 按钮关闭字体对话框：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/4448d866-eb2e-407b-a9ef-97ac098f20d8.png)

所选字体和样式的效果将显示在 Text Edit 小部件中显示的文本上，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/48b1df37-7b6a-4b51-acce-79ffce0be77e.png)

# 使用文件对话框

在这个示例中，我们将学习使用文件对话框，了解如何执行不同的文件操作，如打开文件和保存文件。

我们将学习创建一个包含两个菜单项 Open 和 Save 的文件菜单。单击 Open 菜单项后，将打开文件打开对话框，帮助浏览和选择要打开的文件。打开文件的文件内容将显示在文本编辑框中。用户甚至可以在需要时更新文件内容。在对文件进行所需的修改后，当用户从文件菜单中单击 Save 选项时，文件内容将被更新。

# 准备工作

在这个教程中，我们将使用`QFileDialog`类，该类显示一个对话框，允许用户选择文件或目录。文件可以用于打开和保存。

在这个教程中，我将使用`QFileDialog`类的以下两种方法：

+   `getOpenFileName()`: 该方法打开文件对话框，使用户可以浏览目录并打开所需的文件。`getOpenFileName()`方法的语法如下：

```py
file_name = QFileDialog.getOpenFileName(self, dialog_title, path, filter)
```

在上述代码中，`filter`表示文件扩展名；它确定要显示的文件类型，例如如下所示：

```py
file_name = QFileDialog.getOpenFileName(self, 'Open file', '/home')

In the preceding example, file dialog is opened that shows all the files of home directory to browse from.

file_name = QFileDialog.getOpenFileName(self, 'Open file', '/home', "Images (*.png *.jpg);;Text files (.txt);;XML files (*.xml)")
```

在上面的示例中，您可以看到来自`home`目录的文件。对话框中将显示扩展名为`.png`、`.jpg`、`.txt`和`.xml`的文件。

+   `getSaveFileName()`: 该方法打开文件保存对话框，使用户可以以所需的名称和所需的文件夹保存文件。`getSaveFileName()`方法的语法如下：

```py
file_name = QFileDialog.getSaveFileName(self, dialog_title, path, filter, options)
```

`options`表示如何运行对话框的各种选项，例如，请查看以下代码：

```py
file_name, _ = QFileDialog.getSaveFileName(self,"QFileDialog.getSaveFileName()","","All Files (*);;Text Files (*.txt)", options=options)

In the preceding example, the File Save dialog box will be opened allowing you to save the files with the desired extension. If you don't specify the file extension, then it will be saved with the default extension, .txt.
```

# 如何操作...

让我们基于主窗口模板创建一个新的应用程序。主窗口模板默认包含顶部的菜单：

1.  我们甚至可以使用两个按钮来启动文件打开对话框和文件保存对话框，但使用菜单项来启动文件操作将给人一种实时应用程序的感觉。

1.  主窗口模板中的默认菜单栏显示“Type Here”代替菜单名称。

1.  “Type Here”选项表示用户可以输入所需的菜单名称，替换“Type Here”文本。让我们输入`File`，在菜单栏中创建一个菜单。

1.  按下*Enter*键后，术语“Type Here”将出现在文件菜单下的菜单项中。

1.  在文件菜单中将 Open 作为第一个菜单项。

1.  在创建第一个菜单项 Open 后按下*Enter*键后，术语“Type Here”将出现在 Open 下方。

1.  用菜单项 Save 替换 Type Here。

1.  创建包含两个菜单项 Open 和 Save 的文件菜单后

1.  应用程序将显示如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/b905aec6-f952-4af1-aeb4-ebab19256086.png)

在属性编辑器窗口下方的操作编辑器窗口中，可以看到 Open 和 Save 菜单项的默认对象名称分别为`actionOpen`和`actionSave`。操作编辑器窗口中的 Shortcut 选项卡目前为空，因为尚未为任何菜单项分配快捷键：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/f68b6bba-5a63-43b9-b8b2-5d1fbc82a9e3.png)

1.  要为 Open 菜单项分配快捷键，双击`actionOpen`菜单项的 Shortcut 选项卡中的空白处。您将得到如下截图所示的对话框：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/836d5b52-ff7e-4240-b084-25b0a393679f.png)

文本、对象名称和工具提示框会自动填充默认文本。

1.  单击 Shortcut 框以将光标放置在该框中，并按下*Ctrl*和*O*键，将*Ctrl* + *O*分配为 Open 菜单项的快捷键。

1.  在`actionSave`菜单项的 Shortcut 选项卡的空白处双击，并在打开的对话框的 Shortcut 框中按下*Ctrl* + *S*。

1.  在为两个菜单项 Open 和 Save 分配快捷键后。操作编辑器窗口将显示如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/5e2020b6-9dfd-4a42-a2b4-304bcd498027.png)

使用 Qt Designer 创建的用户界面存储在`.ui`文件中，这是一个 XML 文件。在应用`pyuic5`命令后，XML 文件将被转换为 Python 代码。生成的 Python 脚本`demoFileDialog.py`可以在本书的源代码包中找到。`demoFileDialog.py`脚本将用作头文件，并将在另一个 Python 脚本文件中导入，该文件将调用此用户界面设计、“文件”菜单及其相应的菜单项。

1.  创建另一个名为`callFileDialog.pyw`的 Python 文件，并将`demoFileDialog.py`代码导入其中：

```py
import sys
from PyQt5.QtWidgets import QMainWindow, QApplication, QAction, QFileDialog
from demoFileDialog import *
class MyForm(QMainWindow):
    def __init__(self):
        super().__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.ui.actionOpen.triggered.connect(self.openFileDialog)
        self.ui.actionSave.triggered.connect(self.saveFileDialog)
        self.show()
    def openFileDialog(self):
        fname = QFileDialog.getOpenFileName(self, 'Open file', 
        '/home')
        if fname[0]:
            f = open(fname[0], 'r')
        with f:
            data = f.read()
            self.ui.textEdit.setText(data)
    def saveFileDialog(self):
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        fileName, _ = QFileDialog.getSaveFileName(self,
        "QFileDialog.
        getSaveFileName()","","All Files (*);;Text Files (*.txt)",   
        options=options)
        f = open(fileName,'w')
        text = self.ui.textEdit.toPlainText()
        f.write(text)
        f.close()
if __name__=="__main__":
    app = QApplication(sys.argv)
    w = MyForm()
    w.show()
    sys.exit(app.exec_())
```

# 它是如何工作的...

在`callFileDialog.pyw`文件中，您可以看到具有`objectName`、`actionOpen`的“打开”菜单项的 click()事件连接到`openFileDialog`方法；当用户单击“打开”菜单项时，将调用`openFileDialog`方法。类似地，“保存”菜单项的 click()事件与`objectName`、`actionSave`连接到`saveFileDialog`方法；当用户单击“保存”菜单项时，将调用`saveFileDialog`方法。

在`openFileDialog`方法中，通过调用`QFileDialog`类的`getOpenFileName`方法打开文件对话框。打开文件对话框使用户能够浏览目录并选择要打开的文件。选择文件后，当用户单击“确定”按钮时，所选文件名将被分配给`fname`变量。文件以只读模式打开，并且文件内容被读取并分配给文本编辑小部件；也就是说，文件内容显示在文本编辑小部件中。

在文本编辑小部件中显示的文件内容进行更改后，当用户从文件对话框中单击“保存”菜单项时，将调用`saveFileDialog()`方法。

在`saveFileDialog()`方法中，调用`QFileDialog`类上的`getSaveFileName()`方法，将打开文件保存对话框。您可以在相同位置使用相同名称保存文件，或者使用其他名称。如果在相同位置提供相同的文件名，则单击“确定”按钮后，将会出现一个对话框，询问您是否要用更新的内容覆盖原始文件。提供文件名后，该文件将以写入模式打开，并且文本编辑小部件中的内容将被读取并写入文件。也就是说，文本编辑小部件中可用的更新文件内容将被写入提供的文件名。

运行应用程序后，您会发现一个带有两个菜单项“打开”和“保存”的文件菜单，如下面的屏幕截图所示。您还可以看到“打开”和“保存”菜单项的快捷键：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/e8b9094f-1160-4842-b63f-ed080a134dd5.png)

单击文件菜单中的“打开”菜单项，或按下快捷键*Ctrl* + *O*，您将获得打开文件对话框，如下面的屏幕截图所示。您可以浏览所需的目录并选择要打开的文件。选择文件后，您需要从对话框中单击“打开”按钮：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/147ba560-0280-49a9-b9fb-8c6a6c6d98ef.png)

所选文件的内容将显示在文本编辑框中，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/3155d9b5-2c8f-4450-b4a5-b16fb00e9a18.png)

在文本编辑框中显示的文件内容进行修改后，当用户从文件菜单中单击“保存”菜单项时，将调用`getSaveFileName`方法以显示保存文件对话框。让我们使用原始名称保存文件，然后单击“保存”按钮，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/7e2a8d8f-0369-42b2-b5f6-32582404514d.png)

因为文件将以相同的名称保存，您将收到一个对话框，询问是否要用新内容替换原始文件，如下面的屏幕截图所示。单击“是”以使用新内容更新文件：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/f629f0a0-3d64-4e81-9aa3-13fefe6f9a13.png)


# 第十七章：理解布局

在本章中，我们将重点关注以下主题：

+   使用水平布局

+   使用垂直布局

+   使用网格布局

+   使用表单布局

# 理解布局

正如其名称所示，布局用于以所需格式排列小部件。在布局中排列某些小部件时，自动将某些尺寸和对齐约束应用于小部件。例如，增大窗口的尺寸时，布局中的小部件也会增大，以利用增加的空间。同样，减小窗口的尺寸时，布局中的小部件也会减小。以下问题出现了：布局如何知道小部件的推荐尺寸是多少？

基本上，每个小部件都有一个名为 sizeHint 的属性，其中包含小部件的推荐尺寸。当窗口调整大小并且布局大小也改变时，通过小部件的 sizeHint 属性，布局管理器知道小部件的尺寸要求。

为了在小部件上应用尺寸约束，可以使用以下两个属性：

+   最小尺寸：如果窗口大小减小，小部件仍然不会变得比最小尺寸属性中指定的尺寸更小。

+   最大尺寸：同样，如果窗口增大，小部件不会变得比最大尺寸属性中指定的尺寸更大。

当设置了前述属性时，sizeHint 属性中指定的值将被覆盖。

要在布局中排列小部件，只需选择所有小部件，然后单击工具栏上的“布局管理器”。另一种方法是右键单击以打开上下文菜单。从上下文菜单中，可以选择“布局”菜单选项，然后从弹出的子菜单中选择所需的布局。

在选择所需的布局后，小部件将以所选布局布置，并且在运行时不可见的小部件周围会有一条红线表示布局。要查看小部件是否正确布置，可以通过选择“表单”、“预览”或*Ctrl* + *R*来预览表单。要打破布局，选择“表单”、“打破布局”，输入*Ctrl* + *O*，或从工具栏中选择“打破布局”图标。

布局可以嵌套。

以下是 Qt Designer 提供的布局管理器：

+   水平布局

+   垂直布局

+   网格布局

+   表单布局

# 间隔器

为了控制小部件之间的间距，使用水平和垂直间隔器。当两个小部件之间放置水平间隔器时，两个小部件将被推到尽可能远的左右两侧。如果窗口大小增加，小部件的尺寸不会改变，额外的空间将被间隔器占用。同样，当窗口大小减小时，间隔器会自动减小，但小部件的尺寸不会改变。

间隔器会扩展以填充空白空间，并在空间减小时收缩。

让我们看看在水平框布局中排列小部件的步骤。

# 使用水平布局

水平布局将小部件在一行中排列，即使用水平布局水平对齐小部件。让我们通过制作一个应用程序来理解这个概念。

# 如何做...

在这个应用程序中，我们将提示用户输入电子邮件地址和密码。这个配方的主要重点是理解如何水平对齐两对标签和行编辑小部件。以下是创建此应用程序的逐步过程：

1.  让我们创建一个基于没有按钮的对话框模板的应用程序，并通过将两个标签、两个行编辑和一个按钮小部件拖放到表单上，来添加两个`QLabel`、两个`QLineEdit`和一个`QPushButton`小部件。

1.  将两个标签小部件的文本属性设置为`姓名`和`电子邮件地址`。

1.  还要将按钮小部件的文本属性设置为`提交`。

1.  由于此应用程序的目的是了解布局而不是其他任何内容，因此我们不会设置应用程序中任何小部件的 objectName 属性。

现在表单将显示如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/a58fadae-ef2c-4415-b9f1-a50a23a0f840.png)

1.  我们将在每对 Label 和 LineEdit 小部件上应用水平布局。因此，单击文本为`Name`的 Label 小部件，并保持按住*Ctrl*键，然后单击其旁边的 LineEdit 小部件。

您可以使用*Ctrl* +左键选择多个小部件。

1.  选择 Label 和 LineEdit 小部件后，右键单击并从打开的上下文菜单中选择布局菜单选项。

1.  选择布局菜单选项后，屏幕上将出现几个子菜单选项；选择水平布局子菜单选项。两个 Label 和 LineEdit 小部件将水平对齐，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/bdc1cac6-e00f-4061-8483-08bdba5442ce.png)

1.  如果您想要打破布局怎么办？这很简单：您可以随时通过选择布局并右键单击来打破任何布局。上下文菜单将弹出；从上下文菜单中选择布局菜单选项，然后选择打破布局子菜单选项。

1.  要水平对齐文本为`Email Address`的第二对 Label 小部件和其旁边的 LineEdit 小部件，请重复步骤 6 和 7 中提到的相同过程。这对 Label 和 LineEdit 小部件也将水平对齐，如下截图所示。

您可以看到一个红色的矩形围绕着这两个小部件。这个红色的矩形是水平布局窗口：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/4539ec46-5518-4979-b6a9-5fd9edd6ecf3.png)

1.  要在第一对 Label 和 LineEdit 小部件之间创建一些空间，请从小部件框的间隔器选项卡中拖动水平间隔器小部件，并将其放置在文本为`Name`的 Label 小部件和其旁边的 LineEdit 小部件之间。

水平间隔器小部件最初占据两个小部件之间的默认空间。间隔器显示为表单上的蓝色弹簧。

1.  通过拖动其节点来调整水平间隔器的大小，以限制 LineEdit 小部件的宽度，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/76bf6cf9-c68b-43bd-8db9-9931a47f0906.png)

1.  从第一对 Label 和 LineEdit 小部件的水平布局小部件的红色矩形中选择，并将其向右拖动，使其宽度等于第二对小部件。

1.  拖动水平布局小部件时，水平间隔器将增加其宽度，以消耗两个小部件之间的额外空白空间，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/8404860e-69fe-4ea9-a15a-d36755fb2ef8.png)

1.  将应用程序保存为`demoHorizontalLayout.ui`。

使用 Qt Designer 创建的用户界面存储在`.ui`文件中，这是一个 XML 文件，我们需要将其转换为 Python 代码。要进行转换，您需要打开命令提示符窗口并导航到保存文件的文件夹，然后发出以下命令行：

```py
C:\Pythonbook\PyQt5>pyuic5 demoHorizontalLayout.ui -o demoHorizontalLayout.py
```

Python 脚本文件`demoHorizontalLayout.py`可能包含以下代码：

```py
from PyQt5 import QtCore, QtGui, QtWidgets
class Ui_Dialog(object):
    def setupUi(self, Dialog):
        Dialog.setObjectName("Dialog")
        Dialog.resize(483, 243)
        self.pushButton = QtWidgets.QPushButton(Dialog)
        self.pushButton.setGeometry(QtCore.QRect(120, 130, 111, 
        23))
        font = QtGui.QFont()
        font.setPointSize(12)
        self.pushButton.setFont(font)
        self.pushButton.setObjectName("pushButton")
        self.widget = QtWidgets.QWidget(Dialog)
        self.widget.setGeometry(QtCore.QRect(20, 30, 271, 27))
        self.widget.setObjectName("widget")
        self.horizontalLayout = QtWidgets.QHBoxLayout(self.widget)
        self.horizontalLayout.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.label = QtWidgets.QLabel(self.widget)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.label.setFont(font)
        self.label.setObjectName("label")
        self.horizontalLayout.addWidget(self.label)
        spacerItem = QtWidgets.QSpacerItem(40, 20, QtWidgets.
        QSizePolicy.Expanding,QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacerItem)
        self.lineEdit = QtWidgets.QLineEdit(self.widget)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.lineEdit.setFont(font)
        self.lineEdit.setObjectName("lineEdit")
        self.horizontalLayout.addWidget(self.lineEdit)
        self.widget1 = QtWidgets.QWidget(Dialog)
        self.widget1.setGeometry(QtCore.QRect(20, 80, 276, 27))
        self.widget1.setObjectName("widget1")
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout(self.
        widget1)
        self.horizontalLayout_2.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.label_2 = QtWidgets.QLabel(self.widget1)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.label_2.setFont(font)
        self.label_2.setObjectName("label_2")
        self.horizontalLayout_2.addWidget(self.label_2)
        self.lineEdit_2 = QtWidgets.QLineEdit(self.widget1)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.lineEdit_2.setFont(font)
        self.lineEdit_2.setObjectName("lineEdit_2")
        self.horizontalLayout_2.addWidget(self.lineEdit_2)
        self.retranslateUi(Dialog)
        QtCore.QMetaObject.connectSlotsByName(Dialog)
    def retranslateUi(self, Dialog):
        _translate = QtCore.QCoreApplication.translate
        Dialog.setWindowTitle(_translate("Dialog", "Dialog"))
        self.pushButton.setText(_translate("Dialog", "Submit"))
        self.label.setText(_translate("Dialog", "Name"))
        self.label_2.setText(_translate("Dialog", "Email Address"))
if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    Dialog = QtWidgets.QDialog()
    ui = Ui_Dialog()
    ui.setupUi(Dialog)
    Dialog.show()
    sys.exit(app.exec_())
```

# 它是如何工作的...

您可以在代码中看到，一个具有默认 objectName 属性`lineEdit`的 LineEdit 小部件和一个具有默认 objectName 属性为**label**的 Label 小部件被放置在表单上。使用水平布局小部件水平对齐 LineEdit 和 Label 小部件。水平布局小部件具有默认的 objectName 属性`horizontalLayout`。在对齐 Label 和 LineEdit 小部件时，两个小部件之间的水平空间被减小。因此，在 Label 和 LineEdit 小部件之间保留了一个间隔。第二对 Label 具有默认的 objectName 属性`label_2`和 LineEdit 小部件具有默认的 objectName 属性`lineEdit_2`，通过具有默认 objectName 属性`horizontalLayout_2`的水平布局水平对齐。

运行应用程序后，您会发现两对标签和行编辑小部件水平对齐，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/0e8766db-b9a9-4dde-ab8e-fb23c08ebe42.png)

# 使用垂直布局

垂直布局将选定的小部件垂直排列，以列的形式一个接一个地排列。在下面的应用程序中，您将学习如何在垂直布局中放置小部件。

# 如何做...

在这个应用程序中，我们将提示用户输入姓名和电子邮件地址。用于输入姓名和电子邮件地址的标签和文本框，以及提交按钮，将通过垂直布局垂直排列。以下是创建应用程序的步骤：

1.  启动 Qt Designer 并基于无按钮对话框模板创建一个应用程序，然后通过将两个标签、两个行编辑和一个 `QPushButton` 小部件拖放到表单上，向表单添加两个`QLabel`、两个`QlineEdit`和一个 `QPushButton` 小部件。

1.  将两个标签小部件的文本属性设置为`Name`和`Email Address`。

1.  将提交按钮的文本属性设置为`Submit`。因为这个应用程序的目的是理解布局，而不是其他任何东西，所以我们不会设置应用程序中任何小部件的 objectName 属性。表单现在将显示如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/6eb17343-a136-4675-af5d-5c062e558a71.png)

1.  在对小部件应用垂直布局之前，我们需要将小部件水平对齐。因此，我们将在每对标签和行编辑小部件上应用水平布局小部件。因此，点击文本为`Name`的标签小部件，并保持*Ctrl*键按下，然后点击其旁边的行编辑小部件。

1.  在选择标签和行编辑小部件后，右键单击鼠标按钮，并从打开的上下文菜单中选择布局菜单选项。

1.  选择布局菜单选项后，屏幕上会出现几个子菜单选项。选择水平布局子菜单选项。标签和行编辑小部件将水平对齐。

1.  要水平对齐文本为`Email Address`的第二对标签和其旁边的行编辑小部件，请重复前面步骤 5 和 6 中提到的相同过程。您会看到一个红色矩形围绕着这两个小部件。这个红色矩形是水平布局窗口。

1.  要在第一对标签和行编辑小部件之间创建一些空间，请从小部件框的间隔器选项卡中拖动水平间隔器小部件，并将其放在文本为`Name`的标签小部件和其旁边的行编辑小部件之间。水平间隔器将最初占据两个小部件之间的默认空间。

1.  从第一对标签和行编辑小部件中选择 Horizontal Layout 小部件的红色矩形，并将其向右拖动，使其宽度等于第二对的宽度。

1.  拖动水平布局小部件时，水平间隔器将增加其宽度，以消耗两个小部件之间的额外空白空间，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/6a7bfcbd-9828-44f9-a489-35a95e46eb8d.png)

1.  现在，选择三个项目：第一个水平布局窗口、第二个水平布局窗口和提交按钮。在这些多重选择过程中保持*Ctrl*键按下。

1.  选择这三个项目后，右键单击以打开上下文菜单。

1.  从上下文菜单中选择布局菜单选项，然后选择垂直布局子菜单选项。这三个项目将垂直对齐，并且提交按钮的宽度将增加以匹配最宽布局的宽度，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/2331a0a3-0d14-4fb3-bc0f-647a0926d26d.png)

1.  您还可以从工具栏中选择垂直布局图标，以将小部件排列成垂直布局。

1.  如果要控制提交按钮的宽度，可以使用此小部件的 minimumSize 和 maximumSize 属性。您会注意到两个水平布局之间的垂直空间大大减少了。

1.  要在两个水平布局之间创建一些空间，请从小部件框的间隔器选项卡中拖动垂直间隔器小部件，并将其放置在两个水平布局之间。

垂直间隔器最初将占据两个水平布局之间的默认空间

1.  要在第二个水平布局和提交按钮之间创建垂直空间，请拖动垂直间隔器，并将其放置在第二个水平布局和提交按钮之间。

1.  选择垂直布局的红色矩形，并向下拖动以增加其高度。

1.  拖动垂直布局小部件时，垂直间隔器将增加其高度，以消耗两个水平布局和提交按钮之间的额外空白空间，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/205ffd7b-a853-4a5e-a6b2-ee5ecd78cc3a.png)

1.  将应用程序保存为`demoverticalLayout.ui`。

由于我们知道使用 Qt Designer 创建的用户界面存储在`.ui`文件中，这是一个 XML 文件，需要将其转换为 Python 代码。要进行转换，您需要打开命令提示符窗口，并导航到保存文件的文件夹，然后发出以下命令：

```py
C:PyQt5>pyuic5 demoverticalLayout.ui -o demoverticalLayout.py
```

Python 脚本文件`demoverticalLayout.py`可能包含以下代码：

```py
from PyQt5 import QtCore, QtGui, QtWidgets
class Ui_Dialog(object):
    def setupUi(self, Dialog):
        Dialog.setObjectName("Dialog")
        Dialog.resize(407, 211)
        self.widget = QtWidgets.QWidget(Dialog)
        self.widget.setGeometry(QtCore.QRect(20, 30, 278, 161))
        self.widget.setObjectName("widget")
        self.verticalLayout = QtWidgets.QVBoxLayout(self.widget)
        self.verticalLayout.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout.setObjectName("verticalLayout")
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.label = QtWidgets.QLabel(self.widget)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.label.setFont(font)
        self.label.setObjectName("label")
        self.horizontalLayout.addWidget(self.label)
        spacerItem = QtWidgets.QSpacerItem(40, 20, QtWidgets.
        QSizePolicy.Expanding,QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacerItem)
        self.lineEdit = QtWidgets.QLineEdit(self.widget)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.lineEdit.setFont(font)
        self.lineEdit.setObjectName("lineEdit")
        self.horizontalLayout.addWidget(self.lineEdit)
        self.verticalLayout.addLayout(self.horizontalLayout)
        spacerItem1 = QtWidgets.QSpacerItem(20, 40, QtWidgets.
        QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)
        self.verticalLayout.addItem(spacerItem1)
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.label_2 = QtWidgets.QLabel(self.widget)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.label_2.setFont(font)
        self.label_2.setObjectName("label_2")
        self.horizontalLayout_2.addWidget(self.label_2)
        self.lineEdit_2 = QtWidgets.QLineEdit(self.widget)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.lineEdit_2.setFont(font)
        self.lineEdit_2.setObjectName("lineEdit_2")
        self.horizontalLayout_2.addWidget(self.lineEdit_2)
        self.verticalLayout.addLayout(self.horizontalLayout_2)
        spacerItem2 = QtWidgets.QSpacerItem(20, 40, QtWidgets.
        QSizePolicy.Minimum,QtWidgets.QSizePolicy.
        Expanding)
        self.verticalLayout.addItem(spacerItem2)
        self.pushButton = QtWidgets.QPushButton(self.widget)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.pushButton.setFont(font)
        self.pushButton.setObjectName("pushButton")
        self.verticalLayout.addWidget(self.pushButton)
        self.retranslateUi(Dialog)
        QtCore.QMetaObject.connectSlotsByName(Dialog)
    def retranslateUi(self, Dialog):
        _translate = QtCore.QCoreApplication.translate
        Dialog.setWindowTitle(_translate("Dialog", "Dialog"))
        self.label.setText(_translate("Dialog", "Name"))
        self.label_2.setText(_translate("Dialog", "Email Address"))
        self.pushButton.setText(_translate("Dialog", "Submit"))
if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    Dialog = QtWidgets.QDialog()
    ui = Ui_Dialog()
    ui.setupUi(Dialog)
    Dialog.show()
    sys.exit(app.exec_())
```

# 它是如何工作的...

您可以在代码中看到，具有默认 objectName `lineEdit`属性的 Line Edit 小部件和具有默认 objectName `label`属性的 Label 小部件被放置在表单上，并使用具有默认 objectName 属性`horizontalLayout`的水平布局进行水平对齐。在对齐标签和行编辑小部件时，两个小部件之间的水平空间减小了。因此，在标签和行编辑小部件之间保留了一个间隔器。第二对，具有默认 objectName `label_2`属性的 Label 小部件和具有默认 objectName `lineEdit_2`属性的 Line Edit 小部件，使用具有默认 objectName `horizontalLayout_2`属性的水平布局进行水平对齐。然后，使用具有默认`objectName`属性`verticalLayout`的垂直布局对前两个水平布局和具有默认 objectName `pushButton`属性的提交按钮进行垂直对齐。通过在它们之间放置一个水平间隔器，增加了第一对标签和行编辑小部件之间的水平空间。类似地，通过在它们之间放置一个名为`spacerItem1`的垂直间隔器，增加了两个水平布局之间的垂直空间。此外，还在第二个水平布局和提交按钮之间放置了一个名为`spacerItem2`的垂直间隔器，以增加它们之间的垂直空间。

运行应用程序后，您会发现两对标签和行编辑小部件以及提交按钮垂直对齐，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/dd0b7f67-3b15-4336-b924-46487100a488.png)

# 使用网格布局

网格布局将小部件排列在可伸缩的网格中。要了解网格布局小部件如何排列小部件，让我们创建一个应用程序。

# 如何做...

在这个应用程序中，我们将制作一个简单的登录表单，提示用户输入电子邮件地址和密码，然后点击提交按钮。在提交按钮下方，将有两个按钮，取消和忘记密码。该应用程序将帮助您了解这些小部件如何以网格模式排列。以下是创建此应用程序的步骤：

1.  启动 Qt Designer，并基于无按钮的对话框模板创建一个应用程序，然后通过拖放两个 Label、两个 Line Edit 和三个 Push Button 小部件到表单上，将两个`QLabel`、两个`QlineEdit`和三个`QPushButton`小部件添加到表单上。

1.  将两个 Label 小部件的文本属性设置为`Name`和`Email Address`。

1.  将三个 Push Button 小部件的文本属性设置为`Submit`，`Cancel`和`Forgot Password`。

1.  因为此应用程序的目的是了解布局而不是其他任何内容，所以我们不会设置应用程序中任何小部件的 objectName 属性。

1.  为了增加两个 Line Edit 小部件之间的垂直空间，从 Widget Box 的间隔符选项卡中拖动垂直间隔符小部件，并将其放置在两个 Line Edit 小部件之间。垂直间隔符将最初占据两个 Line Edit 小部件之间的空白空间。

1.  为了在第二个 Line Edit 小部件和提交按钮之间创建垂直空间，拖动垂直间隔符小部件并将其放置在它们之间。

应用程序将显示如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/756be524-e34c-4be9-a03c-da094cecfe9a.png)

1.  通过按下*Ctrl*键并单击表单上的所有小部件来选择表单上的所有小部件。

1.  选择所有小部件后，右键单击鼠标按钮以打开上下文菜单。

1.  从上下文菜单中，选择布局菜单选项，然后选择网格布局子菜单选项。

小部件将按照网格中所示的方式对齐：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/cf4b1ac4-bbd7-4c78-b5c9-e7af16062762.png)

1.  为了增加提交和取消按钮之间的垂直空间，从 Widget Box 的间隔符选项卡中拖动垂直间隔符小部件，并将其放置在它们之间。

1.  为了增加取消和忘记密码按钮之间的水平空间，从间隔符选项卡中拖动水平间隔符小部件，并将其放置在它们之间。

现在表格将显示如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/742b1811-bfea-49f2-a3b3-5aa7e38033f8.png)

1.  将应用程序保存为`demoGridLayout.ui`。

使用 Qt Designer 创建的用户界面存储在`.ui`文件中，这是一个 XML 文件，需要转换为 Python 代码。要进行转换，您需要打开命令提示符窗口并导航到保存文件的文件夹，然后发出以下命令：

```py
C:PyQt5>pyuic5 demoGridLayout.ui -o demoGridLayout.py
```

Python 脚本文件`demoGridLayout.py`可能包含以下代码：

```py
from PyQt5 import QtCore, QtGui, QtWidgets
class Ui_Dialog(object):
    def setupUi(self, Dialog):
        Dialog.setObjectName("Dialog")
        Dialog.resize(369, 279)
        self.widget = QtWidgets.QWidget(Dialog)
        self.widget.setGeometry(QtCore.QRect(20, 31, 276, 216))
        self.widget.setObjectName("widget")
        self.gridLayout = QtWidgets.QGridLayout(self.widget)
        self.gridLayout.setContentsMargins(0, 0, 0, 0)
        self.gridLayout.setObjectName("gridLayout")
        self.pushButton = QtWidgets.QPushButton(self.widget)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.pushButton.setFont(font)
        self.pushButton.setObjectName("pushButton")
        self.gridLayout.addWidget(self.pushButton, 4, 0, 1, 5)
        spacerItem = QtWidgets.QSpacerItem(20, 40, QtWidgets.
        QSizePolicy.Minimum,QtWidgets.QSizePolicy.Expanding)
        self.gridLayout.addItem(spacerItem, 5, 0, 1, 1)
        self.label = QtWidgets.QLabel(self.widget)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.label.setFont(font)
        self.label.setObjectName("label")
        self.gridLayout.addWidget(self.label, 0, 0, 1, 1)
        self.label_2 = QtWidgets.QLabel(self.widget)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.label_2.setFont(font)
        self.label_2.setObjectName("label_2")
        self.gridLayout.addWidget(self.label_2, 2, 0, 1, 2)
        self.lineEdit_2 = QtWidgets.QLineEdit(self.widget)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.lineEdit_2.setFont(font)
        self.lineEdit_2.setObjectName("lineEdit_2")
        self.gridLayout.addWidget(self.lineEdit_2, 2, 2, 1, 3)
        self.lineEdit = QtWidgets.QLineEdit(self.widget)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.lineEdit.setFont(font)
        self.lineEdit.setObjectName("lineEdit")
        self.gridLayout.addWidget(self.lineEdit, 0, 2, 1, 3)
        spacerItem1 = QtWidgets.QSpacerItem(20, 40, QtWidgets.
        QSizePolicy.Minimum,QtWidgets.QSizePolicy.Expanding)
        self.gridLayout.addItem(spacerItem1, 3, 1, 1, 1)
        spacerItem2 = QtWidgets.QSpacerItem(20, 40, QtWidgets.
        QSizePolicy.Minimum,QtWidgets.QSizePolicy.Expanding)
        self.gridLayout.addItem(spacerItem2, 1, 2, 1, 3)
        self.pushButton_2 = QtWidgets.QPushButton(self.widget)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.pushButton_2.setFont(font)
        self.pushButton_2.setObjectName("pushButton_2")
        self.gridLayout.addWidget(self.pushButton_2, 6, 0, 1, 3)
        self.pushButton_3 = QtWidgets.QPushButton(self.widget)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.pushButton_3.setFont(font)
        self.pushButton_3.setObjectName("pushButton_3")
        self.gridLayout.addWidget(self.pushButton_3, 6, 4, 1, 1)
        spacerItem3 = QtWidgets.QSpacerItem(40, 20, QtWidgets.
        QSizePolicy.Expanding,QtWidgets.QSizePolicy.Minimum)
        self.gridLayout.addItem(spacerItem3, 6, 3, 1, 1)
        self.retranslateUi(Dialog)
        QtCore.QMetaObject.connectSlotsByName(Dialog)
    def retranslateUi(self, Dialog):
        _translate = QtCore.QCoreApplication.translate
        Dialog.setWindowTitle(_translate("Dialog", "Dialog"))
        self.pushButton.setText(_translate("Dialog", "Submit"))
        self.label.setText(_translate("Dialog", "Name"))
        self.label_2.setText(_translate("Dialog", "Email Address"))
        self.pushButton_2.setText(_translate("Dialog", "Cancel"))
        self.pushButton_3.setText(_translate("Dialog", 
        "Forgot Password"))
if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    Dialog = QtWidgets.QDialog()
    ui = Ui_Dialog()
    ui.setupUi(Dialog)
    Dialog.show()
    sys.exit(app.exec_())
```

# 工作原理...

您可以在代码中看到，具有默认 objectName`lineEdit`属性的 Line Edit 小部件和具有默认 objectName`label`属性的 Label 小部件放置在表单上。类似地，第二对具有默认 objectName`label_2`属性的 Label 小部件和具有默认 objectName`lineEdit_2`属性的 Line Edit 小部件也放置在表单上。通过在它们之间放置名为`spacerItem1`的垂直间隔符，增加了两对 Label 和 Line Edit 小部件之间的垂直空间。还在表单上放置了一个文本为`Submit`，objectName 为`pushButton`的 Push Button 小部件。同样，通过在具有 objectName`label_2`的第二个 Label 和具有 objectName`pushButton`的 Push Button 小部件之间放置名为`spacerItem2`的垂直间隔符，增加了它们之间的垂直空间。另外两个具有默认 objectName 属性`pushButton_2`和`pushButton_3`的 push 按钮也放置在表单上。所有小部件都以默认对象名称`gridLayout`排列在一个可伸缩的网格布局中。具有 object 名称`pushButton`和`pushButton_2`的两个 push 按钮之间的垂直空间通过在它们之间放置名为`spacerItem3`的垂直间隔符来增加。

运行应用程序时，您会发现两对 Label 和 Line Edit 小部件以及提交、取消和忘记密码按钮都排列在一个可伸缩的网格中，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/d581b1d5-be49-44a1-8060-c92f029cd11a.png)

# 使用表单布局

表单布局被认为是几乎所有应用程序中最需要的布局。当显示产品、服务等以及接受用户或客户的反馈或其他信息时，需要这种两列布局。

# 做好准备

表单布局以两列格式排列小部件。就像任何网站的注册表单或任何订单表单一样，表单被分成两列，左侧列显示标签或文本，右侧列显示空文本框。同样，表单布局将小部件排列在左列和右列。让我们使用一个应用程序来理解表单布局的概念。

# 如何做...

在这个应用程序中，我们将创建两列，一列用于显示消息，另一列用于接受用户输入。除了两对用于从用户那里获取输入的 Label 和 Line Edit 小部件之外，该应用程序还将有两个按钮，这些按钮也将按照表单布局排列。以下是创建使用表单布局排列小部件的应用程序的步骤：

1.  启动 Qt Designer，并基于无按钮的对话框模板创建一个应用程序，然后通过拖放两个 Label、两个 LineEdit 和两个 PushButton 小部件到表单上，添加两个`QLabel`、两个`QLineEdit`和两个`QPushButton`小部件。

1.  将两个 Label 小部件的文本属性设置为`Name`和`Email Address`。

1.  将两个 Push Button 小部件的文本属性设置为`Cancel`和`Submit`。

1.  因为这个应用程序的目的是理解布局，而不是其他任何东西，所以我们不会设置应用程序中任何小部件的 objectName 属性。

应用程序将显示如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/dc2d8dc1-37b5-43f8-a14a-cd377b5f520a.png)

1.  通过按下*Ctrl*键并单击表单上的所有小部件来选择所有小部件。

1.  选择所有小部件后，右键单击鼠标按钮以打开上下文菜单。

1.  从上下文菜单中，选择布局菜单选项，然后选择表单布局子菜单选项中的布局。

小部件将在表单布局小部件中对齐，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/a757b71e-e5ae-4091-a2ac-7a538975ed84.png)

1.  为了增加两个 Line Edit 小部件之间的垂直空间，请从 Widget Box 的间隔器选项卡中拖动垂直间隔器小部件，并将其放置在它们之间。

1.  为了增加第二个 Line Edit 小部件和提交按钮之间的垂直空间，请从间隔器选项卡中拖动垂直间隔器小部件，并将其放置在它们之间。

1.  选择表单布局小部件的红色矩形，并垂直拖动以增加其高度。两个垂直间隔器将自动增加高度，以利用小部件之间的空白空间。

表单现在将显示如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/7558844e-df8a-4249-9389-bfe217334b5f.png)

1.  将应用程序保存为`demoFormLayout.ui`。

使用 Qt Designer 创建的用户界面存储在`.ui`文件中，这是一个 XML 文件，需要转换为 Python 代码。要进行转换，您需要打开命令提示符窗口，并导航到保存文件的文件夹，然后发出以下命令：

```py
C:PyQt5>pyuic5 demoFormLayout.ui -o demoFormLayout.py
```

Python 脚本文件`demoFormLayout.py`可能包含以下代码：

```py
from PyQt5 import QtCore, QtGui, QtWidgets
class Ui_Dialog(object):
    def setupUi(self, Dialog):
        Dialog.setObjectName("Dialog")
        Dialog.resize(407, 211)
        self.widget = QtWidgets.QWidget(Dialog)
        self.widget.setGeometry(QtCore.QRect(20, 30, 276, 141))
        self.widget.setObjectName("widget")
        self.formLayout = QtWidgets.QFormLayout(self.widget)
        self.formLayout.setContentsMargins(0, 0, 0, 0)
        self.formLayout.setObjectName("formLayout")
        self.label = QtWidgets.QLabel(self.widget)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.label.setFont(font)
        self.label.setObjectName("label")
        self.formLayout.setWidget(0, QtWidgets.QFormLayout.
        LabelRole,self.label)
        self.lineEdit = QtWidgets.QLineEdit(self.widget)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.lineEdit.setFont(font)
        self.lineEdit.setObjectName("lineEdit")
        self.formLayout.setWidget(0, QtWidgets.QFormLayout.
        FieldRole,self.lineEdit)
        self.label_2 = QtWidgets.QLabel(self.widget)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.label_2.setFont(font)
        self.label_2.setObjectName("label_2")
        self.formLayout.setWidget(2, QtWidgets.QFormLayout.
        LabelRole,self.label_2)
        self.lineEdit_2 = QtWidgets.QLineEdit(self.widget)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.lineEdit_2.setFont(font)
        self.lineEdit_2.setObjectName("lineEdit_2")
        self.formLayout.setWidget(2, QtWidgets.QFormLayout.
        FieldRole, self.lineEdit_2)
        self.pushButton_2 = QtWidgets.QPushButton(self.widget)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.pushButton_2.setFont(font)
        self.pushButton_2.setObjectName("pushButton_2")
        self.formLayout.setWidget(4, QtWidgets.QFormLayout.
        LabelRole,self.pushButton_2)
        self.pushButton = QtWidgets.QPushButton(self.widget)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.pushButton.setFont(font)
        self.pushButton.setObjectName("pushButton")
        self.formLayout.setWidget(4, QtWidgets.QFormLayout.
        FieldRole,self.pushButton)
        spacerItem = QtWidgets.QSpacerItem(20, 40, QtWidgets.
        QSizePolicy.Minimum,QtWidgets.QSizePolicy.Expanding)
        self.formLayout.setItem(1, QtWidgets.QFormLayout.FieldRole, 
        spacerItem)
        spacerItem1 = QtWidgets.QSpacerItem(20, 40, QtWidgets.
        QSizePolicy.Minimum,QtWidgets.QSizePolicy.Expanding)
        self.formLayout.setItem(3, QtWidgets.QFormLayout.FieldRole, 
        spacerItem1)
        self.retranslateUi(Dialog)
        QtCore.QMetaObject.connectSlotsByName(Dialog)
    def retranslateUi(self, Dialog):
        _translate = QtCore.QCoreApplication.translate
        Dialog.setWindowTitle(_translate("Dialog", "Dialog"))
        self.label.setText(_translate("Dialog", "Name"))
        self.label_2.setText(_translate("Dialog", "Email Address"))
        self.pushButton_2.setText(_translate("Dialog", "Cancel"))
        self.pushButton.setText(_translate("Dialog", "Submit"))
if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    Dialog = QtWidgets.QDialog()
    ui = Ui_Dialog()
    ui.setupUi(Dialog)
    Dialog.show()
    sys.exit(app.exec_())
```

# 它是如何工作的...

您可以在代码中看到，一个带有默认 objectName `lineEdit`属性的 Line Edit 小部件和一个带有默认 objectName `labels`属性的 Label 小部件被放置在表单上。同样，第二对，一个带有默认 objectName `label_2`属性的 Label 小部件和一个带有默认 objectName `lineEdit_2`属性的 Line Edit 小部件被放置在表单上。两个带有 object names `pushButton`和`pushButton_2`的按钮被放置在表单上。所有六个小部件都被选中，并使用默认 objectName `formLayout`属性的表单布局小部件以两列格式对齐。

运行应用程序时，您会发现两对 Label 和 Line Edit 小部件以及取消和提交按钮被排列在表单布局小部件中，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/d7c6b285-ad2e-4171-8937-c2346b4f9166.png)


# 第十八章：网络和管理大型文档

在本章中，我们将学习如何使用网络概念以及如何以块的形式查看大型文档。我们将涵盖以下主题：

+   创建一个小型浏览器

+   创建一个服务器端应用程序

+   建立客户端-服务器通信

+   创建一个可停靠和可浮动的登录表单

+   多文档界面

+   使用选项卡小部件在部分中显示信息

+   创建自定义菜单栏

# 介绍

设备屏幕上的空间总是有限的，但有时您会遇到这样的情况：您想在屏幕上显示大量信息或服务。在这种情况下，您可以使用可停靠的小部件，这些小部件可以在屏幕的任何位置浮动；MDI 可以根据需要显示多个文档；选项卡小部件框可以显示不同块中的信息；或者菜单可以在单击菜单项时显示所需的信息。此外，为了更好地理解网络概念，您需要了解客户端和服务器如何通信。本章将帮助您了解所有这些。

# 创建一个小型浏览器

现在让我们学习一种显示网页或 HTML 文档内容的技术。我们将简单地使用 LineEdit 和 PushButton 小部件，以便用户可以输入所需站点的 URL，然后点击 PushButton 小部件。单击按钮后，该站点将显示在自定义小部件中。让我们看看。

在这个示例中，我们将学习如何制作一个小型浏览器。因为 Qt Designer 没有包含任何特定的小部件，所以这个示例的重点是让您了解如何将自定义小部件提升为`QWebEngineView`，然后可以用于显示网页。

应用程序将提示输入 URL，当用户输入 URL 并点击“Go”按钮后，指定的网页将在`QWebEngineView`对象中打开。

# 如何做...

在这个示例中，我们只需要三个小部件：一个用于输入 URL，第二个用于点击按钮，第三个用于显示网站。以下是创建一个简单浏览器的步骤：

1.  基于没有按钮的对话框模板创建一个应用程序。

1.  通过拖放 Label、LineEdit、PushButton 和 Widget 将`QLabel`、`QLineEdit`、`QPushButton`和`QWidget`小部件添加到表单中。

1.  将 Label 小部件的文本属性设置为“输入 URL”。

1.  将 PushButton 小部件的文本属性设置为`Go`。

1.  将 LineEdit 小部件的 objectName 属性设置为`lineEditURL`，将 PushButton 小部件的 objectName 属性设置为`pushButtonGo`。

1.  将应用程序保存为`demoBrowser.ui`。

表单现在将显示如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/7edee36a-8e27-42e5-b7b6-de89b3c3fd4c.png)

1.  下一步是将`QWidget`提升为`QWebEngineView`，因为要显示网页，需要`QWebEngineView`。

1.  通过右键单击 QWidget 对象并从弹出菜单中选择“提升为...”选项来提升`QWidget`对象。

1.  在弹出的对话框中，将基类名称选项保留为默认的 QWidget。

1.  在 Promoted 类名框中输入`QWebEngineView`，在头文件框中输入`PyQt5.QtWebEngineWidgets`。

1.  选择 Promote 按钮，将 QWidget 提升为`QWebEngineView`类，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/03e31411-d4ea-45fe-997b-13b698a4aebe.png)

使用 Qt Designer 创建的用户界面存储在`.ui`文件中，这是一个 XML 文件，需要转换为 Python 代码。

1.  要进行转换，您需要打开命令提示符窗口并导航到保存文件的文件夹，然后发出以下命令：

```py
C:\Pythonbook\PyQt5>pyuic5 demoBrowser.ui -o demoBrowser.py
```

您可以在本书的源代码包中看到自动生成的 Python 脚本文件`demoBrowser.py`。

1.  将上述代码视为一个头文件，并将其导入到将调用其用户界面设计的文件中。

1.  让我们创建另一个名为`callBrowser.pyw`的 Python 文件，并将`demoBrowser.py`代码导入其中：

```py
import sys
from PyQt5.QtCore import QUrl
from PyQt5.QtWidgets import QApplication, QDialog
from PyQt5.QtWebEngineWidgets import QWebEngineView
from demoBrowser import *
class MyForm(QDialog):
    def __init__(self):
        super().__init__()
        self.ui = Ui_Dialog()
        self.ui.setupUi(self)
        self.ui.pushButtonGo.clicked.connect(self.dispSite)
        self.show()
    def dispSite(self):
        self.ui.widget.load(QUrl(self.ui.lineEditURL.text()))
if __name__=="__main__":
    app = QApplication(sys.argv)
    w = MyForm()
    w.show()
    sys.exit(app.exec_())
```

# 它是如何工作的...

在`demoBrowser.py`文件中，创建了一个名为顶级对象的类，前面加上`Ui_`。也就是说，对于顶级对象`Dialog`，创建了`Ui_Dialog`类，并存储了我们小部件的接口元素。该类包括两个方法，`setupUi()`和`retranslateUi()`。`setupUi()`方法创建了在 Qt Designer 中定义用户界面时使用的小部件。此方法还设置了小部件的属性。`setupUi()`方法接受一个参数，即应用程序的顶级小部件，即`QDialog`的实例。`retranslateUi()`方法翻译了界面。

在`callBrowser.pyw`文件中，您会看到推送按钮小部件的 click()事件连接到`dispSite`方法；在行编辑小部件中输入 URL 后，当用户单击推送按钮时，将调用`dispSite`方法。

`dispSite()`方法调用`QWidget`类的`load()`方法。请记住，`QWidget`对象被提升为`QWebEngineView`类，用于查看网页。`QWebEngineView`类的`load()`方法接收`lineEditURL`对象中输入的 URL，因此指定 URL 的网页将在`QWebEngine`小部件中打开或加载。

运行应用程序时，您会得到一个空的行编辑框和一个推送按钮小部件。在行编辑小部件中输入所需的 URL，然后单击“Go”按钮，您会发现网页在`QWebEngineView`小部件中打开，如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/4f26797c-c0ca-406f-886f-3fb16878c474.png)

# 创建服务器端应用程序

网络在现代生活中扮演着重要角色。我们需要了解两台机器之间的通信是如何建立的。当两台机器通信时，一台通常是服务器，另一台是客户端。客户端向服务器发送请求，服务器通过为客户端提出的请求提供响应。

在本示例中，我们将创建一个客户端-服务器应用程序，在客户端和服务器之间建立连接，并且每个都能够向另一个传输文本消息。也就是说，将创建两个应用程序，并且将同时执行，一个应用程序中编写的文本将出现在另一个应用程序中。

# 如何做...

让我们首先创建一个服务器应用程序，如下所示：

1.  基于无按钮对话框模板创建应用程序。

1.  通过将标签、文本编辑、行编辑和推送按钮小部件拖放到表单上，向表单添加`QLabel`、`QTextEdit`、`QLineEdit`和`QPushButton`。

1.  将标签小部件的文本属性设置为“服务器”，以指示这是服务器应用程序。

1.  将推送按钮小部件的文本属性设置为“发送”。

1.  将文本编辑小部件的对象名称属性设置为`textEditMessages`。

1.  将行编辑小部件的对象名称属性设置为`lineEditMessage`。

1.  将推送按钮小部件设置为`pushButtonSend`。

1.  将应用程序保存为`demoServer.ui`。表单现在将显示如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/88690655-831b-4b2a-a84e-5c04aabf9418.png)

使用 Qt Designer 创建的用户界面存储在`.ui`文件中，这是一个 XML 文件，需要转换为 Python 代码。生成文件`demoServer.py`的代码可以在本书的源代码包中看到。

# 工作原理...

`demoServer.py`文件将被视为头文件，并将被导入到另一个 Python 文件中，该文件将使用头文件的 GUI 并在服务器和客户端之间传输数据。但在此之前，让我们为客户端应用程序创建一个 GUI。客户端应用程序的 GUI 与服务器应用程序完全相同，唯一的区别是该应用程序顶部的标签小部件将显示文本“客户端”。

`demoServer.py`文件是我们拖放到表单上的 GUI 小部件的生成 Python 脚本。

要在服务器和客户端之间建立连接，我们需要一个套接字对象。要创建套接字对象，您需要提供以下两个参数：

+   **套接字地址**：套接字地址使用特定的地址系列表示。每个地址系列都需要一些参数来建立连接。在本应用程序中，我们将使用`AF_INET`地址系列。`AF_INET`地址系列需要一对（主机，端口）来建立连接，其中参数`host`是主机名，可以是字符串格式、互联网域表示法或 IPv4 地址格式，参数`port`是用于通信的端口号。

+   **套接字类型**：套接字类型通过几个常量表示：`SOCK_STREAM`、`SOCK_DGRAM`、`SOCK_RAW`、`SOCK_RDM`和`SOCK_SEQPACKET`。在本应用程序中，我们将使用最常用的套接字类型`SOCK_STREAM`。

应用程序中使用`setsockopt()`方法设置给定套接字选项的值。它包括以下两个基本参数：

+   `SOL_SOCKET`：此参数是套接字层本身。它用于协议无关的选项。

+   `SO_REUSEADDR`：此参数允许其他套接字`bind()`到此端口，除非已经有一个活动的监听套接字绑定到该端口。

您可以在先前的代码中看到，创建了一个`ServerThread`类，它继承了 Python 的线程模块的`Thread`类。`run()`函数被重写，其中定义了`TCP_IP`和`TCP_HOST`变量，并且`tcpServer`与这些变量绑定。

此后，服务器等待看是否有任何客户端连接。对于每个新的客户端连接，服务器在`while`循环内创建一个新的`ClientThread`。这是因为为每个客户端创建一个新线程不会阻塞服务器的 GUI 功能。最后，线程被连接。

# 建立客户端-服务器通信

在这个教程中，我们将学习如何制作一个客户端，并看到它如何向服务器发送消息。主要思想是理解消息是如何发送的，服务器如何监听端口，以及两者之间的通信是如何建立的。

# 如何做...

要向服务器发送消息，我们将使用`LineEdit`和`PushButton`小部件。在单击推送按钮时，LineEdit 小部件中编写的消息将传递到服务器。以下是创建客户端应用程序的逐步过程：

1.  基于没有按钮的对话框模板创建另一个应用程序。

1.  通过将 Label、TextEdit、LineEdit 和 PushButton 小部件拖放到表单上，向表单添加`QLabel`、`QTextEdit`、`QLineEdit`和`QPushButton`。

1.  将 Label 小部件的文本属性设置为`Client`。

1.  将 PushButton 小部件的文本属性设置为`Send`。

1.  将 TextEdit 小部件的 objectName 属性设置为`textEditMessages`。

1.  将 LineEdit 小部件的 objectName 属性设置为`lineEditMessage`。

1.  将 PushButton 小部件设置为`pushButtonSend`。

1.  将应用程序保存为`demoClient.ui`。

表单现在将显示如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/f513ff3a-a1bc-4cb3-8baf-e2b9e965d3f0.png)

使用 Qt Designer 创建的用户界面存储在`.ui`文件中，这是一个 XML 文件，需要转换为 Python 代码。自动生成的文件`demoClient.py`的代码可以在本书的源代码包中找到。要使用`demoClient.py`文件中创建的 GUI，需要将其导入到另一个 Python 文件中，该文件将使用 GUI 并在服务器和客户端之间传输数据。

1.  创建另一个名为`callServer.pyw`的 Python 文件，并将`demoServer.py`代码导入其中。`callServer.pyw`脚本中的代码如下所示：

```py
import sys, time
from PyQt5 import QtGui
from PyQt5 import QtCore
from PyQt5.QtWidgets import QApplication, QDialog
from PyQt5.QtCore import QCoreApplication
import socket
from threading import Thread
from socketserver import ThreadingMixIn
conn=None
from demoServer import *
class Window(QDialog):
    def __init__(self):
        super().__init__()
        self.ui = Ui_Dialog()
        self.ui.setupUi(self)
        self.textEditMessages=self.ui.textEditMessages
        self.ui.pushButtonSend.clicked.connect(self.dispMessage)
        self.show()

    def dispMessage(self):
        text=self.ui.lineEditMessage.text()
        global conn
        conn.send(text.encode("utf-8"))
        self.ui.textEditMessages.append("Server:   
        "+self.ui.lineEditMessage.text())
        self.ui.lineEditMessage.setText("")
class ServerThread(Thread):
    def __init__(self,window):
        Thread.__init__(self)
        self.window=window
    def run(self):
        TCP_IP = '0.0.0.0'
        TCP_PORT = 80
        BUFFER_SIZE = 1024
        tcpServer = socket.socket(socket.AF_INET,  
        socket.SOCK_STREAM)
        tcpServer.setsockopt(socket.SOL_SOCKET,         
        socket.SO_REUSEADDR, 1)
        tcpServer.bind((TCP_IP, TCP_PORT))
        threads = []
        tcpServer.listen(4)
        while True:
            global conn
            (conn, (ip,port)) = tcpServer.accept()
            newthread = ClientThread(ip,port,window)
            newthread.start()
            threads.append(newthread)
        for t in threads:
            t.join()
class ClientThread(Thread):
    def __init__(self,ip,port,window):
        Thread.__init__(self)
        self.window=window
        self.ip = ip
        self.port = port
    def run(self):
        while True :
            global conn
            data = conn.recv(1024)
            window.textEditMessages.append("Client: 
            "+data.decode("utf-8"))

if __name__=="__main__":
    app = QApplication(sys.argv)
    window = Window()
    serverThread=ServerThread(window)
    serverThread.start()
    window.exec()
    sys.exit(app.exec_())
```

# 工作原理...

在`ClientThread`类中，`run`函数被重写。在`run`函数中，每个客户端等待从服务器接收的数据，并在文本编辑小部件中显示该数据。一个`window`类对象被传递给`ServerThread`类，后者将该对象传递给`ClientThread`，后者又使用它来访问在行编辑元素中编写的内容。

接收到的数据被解码，因为接收到的数据是以字节形式，必须使用 UTF-8 编码转换为字符串。

在前面的部分生成的`demoClient.py`文件需要被视为一个头文件，并且需要被导入到另一个 Python 文件中，该文件将使用头文件的 GUI 并在客户端和服务器之间传输数据。因此，让我们创建另一个名为`callClient.pyw`的 Python 文件，并将`demoClient.py`代码导入其中：

```py
import sys
from PyQt5.QtWidgets import QApplication, QDialog
import socket
from threading import Thread
from socketserver import ThreadingMixIn
from demoClient import *
tcpClientA=None
class Window(QDialog):
    def __init__(self):
        super().__init__()
        self.ui = Ui_Dialog()
        self.ui.setupUi(self)
        self.textEditMessages=self.ui.textEditMessages
        self.ui.pushButtonSend.clicked.connect(self.dispMessage)
        self.show()
    def dispMessage(self):
        text=self.ui.lineEditMessage.text()
        self.ui.textEditMessages.append("Client:  
        "+self.ui.lineEditMessage.text())
        tcpClientA.send(text.encode())
        self.ui.lineEditMessage.setText("")
class ClientThread(Thread):
    def __init__(self,window):
        Thread.__init__(self)
        self.window=window
    def run(self):
        host = socket.gethostname()
        port = 80
        BUFFER_SIZE = 1024
        global tcpClientA
        tcpClientA = socket.socket(socket.AF_INET, 
        socket.SOCK_STREAM)
        tcpClientA.connect((host, port))
        while True:
            data = tcpClientA.recv(BUFFER_SIZE)
            window.textEditMessages.append("Server: 
            "+data.decode("utf-8"))
            tcpClientA.close()
if __name__=="__main__":
    app = QApplication(sys.argv)
    window = Window()
    clientThread=ClientThread(window)
    clientThread.start()
    window.exec()
    sys.exit(app.exec_())
```

`ClientThread`类是一个继承`Thread`类并重写`run`函数的类。在`run`函数中，通过在`socket`类上调用`hostname`方法来获取服务器的 IP 地址；并且，使用端口`80`，客户端尝试连接到服务器。一旦与服务器建立连接，客户端尝试在 while 循环内从服务器接收数据。

从服务器接收数据后，将数据从字节格式转换为字符串格式，并显示在文本编辑小部件中。

我们需要运行两个应用程序来查看客户端-服务器通信。运行`callServer.pyw`文件，您将在以下截图的左侧看到输出，运行`callClient.pyw`文件，您将在右侧看到输出。两者相同；只有顶部的标签有所区别：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/61308f2b-a3b2-4762-8c4f-ed9a4dfe39fc.png)

用户可以在底部的行编辑框中输入文本，然后按下发送按钮。按下发送按钮后，输入的文本将出现在服务器和客户端应用程序的文本编辑框中。文本以`Server:`为前缀，以指示该文本是从服务器发送的，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/e91410d8-0334-44a0-8414-ba6f766587fe.png)

同样，如果在客户端应用程序的行编辑小部件中输入文本，然后按下发送按钮，文本将出现在两个应用程序的文本编辑小部件中。文本将以`Client:`为前缀，以指示该文本已从客户端发送，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/17844150-0e96-41b8-9d78-ff12122757dd.png)

# 创建一个可停靠和可浮动的登录表单

在本教程中，我们将学习创建一个登录表单，该表单将要求用户输入电子邮件地址和密码以进行身份验证。这个登录表单不同于通常的登录表单，因为它是一个可停靠的表单。也就是说，您可以将这个登录表单停靠在窗口的四个边缘之一——顶部、左侧、右侧和底部，甚至可以将其用作可浮动的表单。这个可停靠的登录表单将使用 Dock 小部件创建，所以让我们快速了解一下 Dock 小部件。

# 准备工作

要创建一组可分离的小部件或工具，您需要一个 Dock 小部件。Dock 小部件是使用`QDockWidget`类创建的，它是一个带有标题栏和顶部按钮的容器，用于调整大小。包含一组小部件或工具的 Dock 小部件可以关闭、停靠在停靠区域中，或者浮动并放置在桌面的任何位置。Dock 小部件可以停靠在不同的停靠区域，例如`LeftDockWidgetArea`、`RightDockWidgetArea`、`TopDockWidgetArea`和`BottomDockWidgetArea`。`TopDockWidgetArea`停靠区域位于工具栏下方。您还可以限制 Dock 小部件可以停靠的停靠区域。这样做后，Dock 小部件只能停靠在指定的停靠区域。当将 Dock 窗口拖出停靠区域时，它将成为一个自由浮动的窗口。

以下是控制 Dock 小部件的移动以及其标题栏和其他按钮外观的属性：

| **属性** | **描述** |
| --- | --- |
| `DockWidgetClosable` | 使 Dock 小部件可关闭。 |
| `DockWidgetMovable` | 使 Dock 小部件在停靠区域之间可移动。 |
| `DockWidgetFloatable` | 使 Dock 小部件可浮动，也就是说，Dock 小部件可以从主窗口中分离并在桌面上浮动。 |
| `DockWidgetVerticalTitleBar` | 在 Dock 小部件的左侧显示垂直标题栏。 |
| `AllDockWidgetFeatures` | 它打开属性，如`DockWidgetClosable`，`DockWidgetMovable`和`DockWidgetFloatable`，也就是说，Dock 小部件可以关闭，移动或浮动。 |
| `NoDockWidgetFeatures` | 如果选择，Dock 小部件将无法关闭，移动或浮动。 |

为了制作可停靠的登录表单，我们将使用 Dock 小部件和其他一些小部件。让我们看看逐步的操作步骤。

# 如何做...

让我们在 Dock 小部件中制作一个小的登录表单，提示用户输入其电子邮件地址和密码。由于可停靠，此登录表单可以移动到屏幕上的任何位置，并且可以浮动。以下是创建此应用程序的步骤：

1.  启动 Qt Designer 并创建一个新的主窗口应用程序。

1.  将一个 Dock 小部件拖放到表单上。

1.  拖放您希望在停靠区域或作为浮动窗口在 Dock 小部件中可用的小部件。

1.  在 Dock 小部件上拖放三个 Label 小部件，两个 LineEdit 小部件和一个 PushButton 小部件。

1.  将三个 Label 小部件的文本属性设置为`登录`，`电子邮件地址`和`密码`。

1.  将 Push Button 小部件的文本属性设置为`登录`。

1.  我们将不设置 LineEdit 和 PushButton 小部件的 objectName 属性，并且不会为 PushButton 小部件提供任何代码，因为此应用程序的目的是了解 Dock 小部件的工作原理。

1.  将应用程序保存为`demoDockWidget.ui`。

表单将显示如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/f23980de-4068-42d2-aca1-6e4cf5dfcd66.png)

1.  要启用 Dock 小部件中的所有功能，请选择它并在属性编辑器窗口的功能部分中检查其 AllDockWidgetFeatures 属性，如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/fca7bb78-58e2-446e-a112-ca985a7a692c.png)

在上述屏幕截图中，AllDockWidgetFeatures 属性是使 Dock 小部件可关闭，在停靠时可移动，并且可以在桌面的任何位置浮动。如果选择了 NoDockWidgetFeatures 属性，则功能部分中的所有其他属性将自动取消选中。这意味着所有按钮将从 Dock 小部件中消失，您将无法关闭或移动它。如果希望 Dock 小部件在应用程序启动时显示为可浮动，请在属性编辑器窗口中的功能部分上方检查浮动属性。

查看以下屏幕截图，显示了 Dock 小部件上的各种功能和约束：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/8a6db2f9-92ff-4fb9-9d8c-92b896669a56.png)

执行以下步骤，将所需的功能和约束应用于 Dock 小部件：

1.  在 allowedAreas 部分中检查 AllDockWidgetAreas 选项，以使 Dock 小部件可以停靠在左侧，右侧，顶部和底部的所有 Dock 小部件区域。

1.  此外，通过在属性编辑器窗口中使用 windowTitle 属性，将停靠窗口的标题设置为 Dockable Sign In Form，如上图所示。

1.  检查停靠属性，因为这是使 Dock 小部件可停靠的重要属性。如果未选中停靠属性，则 Dock 小部件无法停靠到任何允许的区域。

1.  将 dockWidgetArea 属性保留其默认值 LeftDockWidgetArea。dockWidgetArea 属性确定您希望停靠窗口小部件在应用程序启动时出现为停靠的位置。dockWidgetArea 属性的 LeftDockWidgetArea 值将使停靠窗口小部件首先出现为停靠在左侧停靠窗口区域。如果在 allowedAreas 部分设置了 NoDockWidgetArea 属性，则 allowedAreas 部分中的所有其他属性将自动取消选择。因此，您可以将停靠窗口移动到桌面的任何位置，但不能将其停靠在主窗口模板的停靠区域中。使用 Qt Designer 创建的用户界面存储在一个`.ui`文件中，这是一个 XML 文件，需要转换为 Python 代码。在 XML 文件上应用`pyuic5`命令行实用程序后，生成的文件是一个 Python 脚本文件`demoDockWidget.py`。您可以在本书的源代码包中看到生成的`demoDockWidget.py`文件的代码。

1.  将`demoDockWidget.py`文件中的代码视为头文件，并将其导入到将调用其用户界面设计的文件中。

1.  创建另一个名为`callDockWidget.pyw`的 Python 文件，并将`demoDockWidget.py`的代码导入其中：

```py
import sys
from PyQt5.QtWidgets import QMainWindow, QApplication
from demoDockWidget import *
class AppWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.show()
if __name__=="__main__":
    app = QApplication(sys.argv)
    w = AppWindow()
    w.show()
    sys.exit(app.exec_())
```

# 工作原理...

如前面的代码所示，导入了必要的模块。创建了一个`AppWindow`类，它继承自基类`QMainWindow`。调用了`QMainWindow`的默认构造函数。

因为每个 PyQt5 应用程序都需要一个应用程序对象，在上面的代码中，通过调用`QApplication()`方法创建了一个名为 app 的应用程序对象。将`sys.argv`参数作为参数传递给`QApplication()`方法，以传递命令行参数和其他外部属性给应用程序。`sys.argv`参数包含命令行参数和其他外部属性（如果有的话）。为了显示界面中定义的小部件，创建了一个名为`w`的`AppWindow`类的实例，并在其上调用了`show()`方法。为了退出应用程序并将代码返回给可能用于错误处理的 Python 解释器，调用了`sys.exit()`方法。

当应用程序执行时，默认情况下会得到一个停靠在左侧可停靠区域的停靠窗口小部件，如下面的屏幕截图所示。这是因为您已经将`dockWidgetArea`属性的值分配给了`LeftDockWidgetArea`：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/81e13139-7926-4a9a-88b9-0681a52e6606.png)

停靠窗口小部件内的小部件不完全可见，因为默认的左侧和可停靠区域比停靠窗口小部件中放置的小部件要窄。因此，您可以拖动停靠窗口小部件的右边框，使所有包含的小部件可见，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/ede66a10-a27a-4042-9199-7976711f57af.png)

您可以将小部件拖动到任何区域。如果将其拖动到顶部，则会停靠在`TopDockWidgetArea`停靠区域，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/b2259d77-1078-4302-9c9c-e1f24625a314.png)

同样，当将停靠窗口小部件拖动到右侧时，它将停靠在`RightDockWidgetArea`中

您可以将停靠窗口小部件拖动到主窗口模板之外，使其成为一个独立的浮动窗口。停靠窗口小部件将显示为一个独立的浮动窗口，并可以移动到桌面的任何位置：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/f01528da-0749-4beb-9fb3-8c921e4cf9c5.png)

# 多文档界面

在这个示例中，我们将学习如何创建一个应用程序，可以同时显示多个文档。我们不仅能够管理多个文档，还将学会以不同的格式排列这些文档。我们将能够使用称为多文档界面的概念来管理多个文档，让我们快速了解一下这个概念。

# 准备工作

通常，一个应用程序提供一个主窗口对应一个文档，这样的应用程序被称为**单文档界面**（**SDI**）应用程序。顾名思义，**多文档界面**（**MDI**）应用程序能够显示多个文档。MDI 应用程序由一个主窗口以及一个菜单栏、一个工具栏和一个中心空间组成。多个文档可以显示在中心空间中，每个文档可以通过各自的子窗口小部件进行管理；在 MDI 中，可以显示多个文档，每个文档都显示在自己的窗口中。这些子窗口也被称为子窗口。

MDI 是通过使用`MdiArea`小部件来实现的。`MdiArea`小部件提供了一个区域，用于显示子窗口。子窗口有标题和按钮，用于显示、隐藏和最大化其大小。每个子窗口可以显示一个单独的文档。可以通过设置`MdiArea`小部件的相应属性，将子窗口以级联或平铺方式排列。`MdiArea`小部件是`QMdiArea`类的一个实例，子窗口是`QMdiSubWindow`的实例。

以下是`QMdiArea`提供的方法：

+   `subWindowList()`: 这个方法返回 MDI 区域中所有子窗口的列表。返回的列表按照通过`WindowOrder()`函数设置的顺序排列。

+   `WindowOrder`：这个静态变量设置了对子窗口列表进行排序的标准。以下是可以分配给这个静态变量的有效值：

+   `CreationOrder`：窗口按照它们创建的顺序返回。这是默认顺序。

+   `StackingOrder`：窗口按照它们叠放的顺序返回，最上面的窗口最后出现在列表中。

+   `ActivationHistoryOrder`：窗口按照它们被激活的顺序返回。

+   `activateNextSubWindow()`: 这个方法将焦点设置为子窗口列表中的下一个窗口。当前窗口的顺序决定了要激活的下一个窗口。

+   `activatePreviousSubWindow()`: 这个方法将焦点设置为子窗口列表中的上一个窗口。当前窗口的顺序决定了要激活的上一个窗口。

+   `cascadeSubWindows()`: 这个方法以级联方式排列子窗口。

+   `tileSubWindows()`: 这个方法以平铺方式排列子窗口。

+   `closeAllSubWindows()`: 这个方法关闭所有子窗口。

+   `setViewMode()`: 这个方法设置 MDI 区域的视图模式。子窗口可以以两种模式查看，子窗口视图和选项卡视图：

+   子窗口视图：这个方法显示带有窗口框架的子窗口（默认）。如果以平铺方式排列，可以看到多个子窗口的内容。它还由一个常量值`0`表示。

+   选项卡视图：在选项卡栏中显示带有选项卡的子窗口。一次只能看到一个子窗口的内容。它还由一个常量值`1`表示。

# 如何做...

让我们创建一个应用程序，其中包含两个文档，每个文档将通过其各自的子窗口显示。我们将学习如何按需排列和查看这些子窗口：

1.  启动 Qt Designer 并创建一个新的主窗口应用程序。

1.  将`MdiArea`小部件拖放到表单上。

1.  右键单击小部件，从上下文菜单中选择“添加子窗口”以将子窗口添加到`MdiArea`小部件中。

当子窗口添加到`MdiArea`小部件时，该小部件将显示为深色背景，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/bfb235c6-0e67-49ea-aad6-142b11a6c7d2.png)

1.  让我们再次右键单击`MdiArea`小部件，并向其添加一个子窗口。

1.  要知道哪一个是第一个，哪一个是第二个子窗口，可以在每个子窗口上拖放一个 Label 小部件。

1.  将放置在第一个子窗口中的 Label 小部件的文本属性设置为`First subwindow`。

1.  将放置在第二个子窗口中的 Label 小部件的文本属性设置为`Second subwindow`，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/4847a248-744d-47d0-b837-3ddeac8fd0dd.png)

`MdiArea`小部件以以下两种模式显示放置在其子窗口中的文档：

+   子窗口视图：这是默认视图模式。在此视图模式下，子窗口可以以级联或平铺方式排列。当子窗口以平铺方式排列时，可以同时看到多个子窗口的内容。

+   选项卡视图：在此模式下，选项卡栏中会显示多个选项卡。选择选项卡时，将显示与之关联的子窗口。一次只能看到一个子窗口的内容。

1.  通过菜单选项激活子窗口视图和选项卡视图模式，双击菜单栏中的 Type Here 占位符，并向其添加两个条目：子窗口视图和选项卡视图。

此外，为了查看子窗口以级联和平铺方式排列时的外观，将两个菜单项 Cascade View 和 Tile View 添加到菜单栏中，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/1aed9dce-6c6e-4c3c-9dc7-9aacb6562892.png)

1.  将应用程序保存为`demoMDI.ui`。使用 Qt Designer 创建的用户界面存储在`.ui`文件中，这是一个 XML 文件，需要转换为 Python 代码。在应用`pyuic5`命令行实用程序时，`.ui`（XML）文件将被转换为 Python 代码：

```py
 C:\Pythonbook\PyQt5>pyuic5 demoMDI.ui -o demoMDI.py.
```

您可以在本书的源代码包中看到生成的 Python 代码`demoMDI.py`。

1.  将`demoMDI.py`文件中的代码视为头文件，并将其导入到您将调用其用户界面设计的文件中。前面的代码中的用户界面设计包括`MdiArea`，用于显示其中创建的子窗口以及它们各自的小部件。我们将要创建的 Python 脚本将包含用于执行不同任务的菜单选项的代码，例如级联和平铺子窗口，将视图模式从子窗口视图更改为选项卡视图，反之亦然。让我们将该 Python 脚本命名为`callMDI.pyw`，并将`demoMDI.py`代码导入其中：

```py
import sys
from PyQt5.QtWidgets import QMainWindow, QApplication, QAction, QFileDialog
from demoMDI import *
class MyForm(QMainWindow):
    def __init__(self):
        super().__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.ui.mdiArea.addSubWindow(self.ui.subwindow)
        self.ui.mdiArea.addSubWindow(self.ui.subwindow_2)
        self.ui.actionSubWindow_View.triggered.connect
        (self.SubWindow_View)
        self.ui.actionTabbed_View.triggered.connect(self.
        Tabbed_View)
        self.ui.actionCascade_View.triggered.connect(self.
        cascadeArrange)
        self.ui.actionTile_View.triggered.connect(self.tileArrange)
        self.show()
    def SubWindow_View(self):
        self.ui.mdiArea.setViewMode(0)
    def Tabbed_View(self):
        self.ui.mdiArea.setViewMode(1)
    def cascadeArrange(self):
        self.ui.mdiArea.cascadeSubWindows()
    def tileArrange(self):
        self.ui.mdiArea.tileSubWindows()
if __name__=="__main__":
    app = QApplication(sys.argv)
    w = MyForm()
    w.show()
    sys.exit(app.exec_())
```

# 工作原理...

在上述代码中，您可以看到具有默认 objectName 属性`subwindow`和`subwindow_2`的两个子窗口被添加到`MdiArea`小部件中。之后，具有 objectName 属性`actionSubWindow_View`、`actionTabbed_View`、`actionCascade_View`和`actionTile_View`的四个菜单选项分别连接到四个方法`SubWindow_View`、`Tabbed_View`、`cascadeArrange`和`tileArrange`。因此，当用户选择子窗口视图菜单选项时，将调用`SubWindow_View`方法。在`SubWindow_View`方法中，通过将`0`常量值传递给`MdiArea`小部件的`setViewMode`方法来激活子窗口视图模式。子窗口视图显示带有窗口框架的子窗口。

类似地，当用户选择选项卡视图菜单选项时，将调用`Tabbed_View`方法。在`Tabbed_View`方法中，通过将`1`常量值传递给`MdiArea`小部件的`setViewMode`方法来激活选项卡视图模式。选项卡视图模式在选项卡栏中显示选项卡，单击选项卡时，将显示关联的子窗口。

选择级联视图菜单选项时，将调用`cascadeArrange`方法，该方法又调用`MdiArea`小部件的`cascadeSubWindows`方法以级联形式排列子窗口。

选择平铺视图菜单选项时，将调用`tileArrange`方法，该方法又调用`MdiArea`小部件的`tileSubWindows`方法以平铺形式排列子窗口。

运行应用程序时，子窗口最初以缩小模式出现在`MdiArea`小部件中，如下面的屏幕截图所示。您可以看到子窗口以及它们的标题和最小化、最大化和关闭按钮：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/1ebe29d9-558d-47d0-b8f1-5a58f3fc8a95.png)

您可以拖动它们的边框到所需的大小。在 Windows 菜单中选择第一个窗口时，子窗口将变为活动状态；选择第二个窗口时，下一个子窗口将变为活动状态。活动子窗口显示为更亮的标题和边界。在下面的截图中，您可以注意到第二个子窗口是活动的。您可以拖动任何子窗口的边界来增加或减少其大小。您还可以最小化一个子窗口，并拖动另一个子窗口的边界以占据整个`MdiArea`小部件的整个宽度。如果在任何子窗口中选择最大化，它将占据`MdiArea`的所有空间，使其他子窗口不可见：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/416296d6-bf06-45ad-a2d8-98efad13ec01.png)

在选择级联时，子窗口以级联模式排列，如下截图所示。如果在级联模式下最大化窗口，则顶部子窗口将占据整个`MdiArea`小部件，将其他子窗口隐藏在其后，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/0db471f4-3caa-4770-99c6-c1bfa496aadd.png)

在选择平铺按钮时，子窗口会展开并平铺。两个子窗口均等地扩展以覆盖整个工作区，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/a869236e-f6a6-4acb-acde-4a1c66edab7f.png)

在选择选项卡视图按钮时，`MdiArea`小部件将从子窗口视图更改为选项卡视图。您可以选择任何子窗口的选项卡使其处于活动状态，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/26183590-38c9-433f-8129-cdb27e2b27b0.png)

# 使用选项卡小部件显示信息的部分

在这个应用程序中，我们将制作一个小型购物车，它将在一个选项卡中显示某些待售产品；在用户从第一个选项卡中选择所需产品后，当用户选择第二个选项卡时，他们将被提示输入首选付款选项。第三个选项卡将要求用户输入交付产品的地址。

我们将使用选项卡小部件使我们能够选择并分块填写所需的信息，所以您一定想知道，选项卡小部件是什么？

当某些信息被分成小节，并且您希望为用户显示所需部分的信息时，您需要使用选项卡小部件。在选项卡小部件容器中，有许多选项卡，当用户选择任何选项卡时，将显示分配给该选项卡的信息。

# 如何做...

以下是逐步创建应用程序以使用选项卡显示信息的过程：

1.  让我们基于没有按钮的对话框模板创建一个新应用程序。

1.  将选项卡小部件拖放到表单上。当您将选项卡小部件拖放到对话框上时，它将显示两个默认选项卡按钮，标有 Tab1 和 Tab2，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/d0bb4b0d-397e-4ec6-9e3f-a24ae20c57a7.png)

1.  您可以向选项卡小部件添加更多选项卡按钮，并通过添加新的选项卡按钮删除现有按钮；右键单击任一选项卡按钮，然后从弹出的菜单中选择“插入页面”。您将看到两个子选项，当前页面之后和当前页面之前。

1.  选择“当前页面之后”子选项以在当前选项卡之后添加一个新选项卡。新选项卡将具有默认文本“页面”，您可以随时更改。我们将要制作的应用程序包括以下三个选项卡：

+   第一个选项卡显示某些产品以及它们的价格。用户可以从第一个选项卡中选择任意数量的产品，然后单击“添加到购物车”按钮。

+   在选择第二个选项卡时，将显示所有付款选项。用户可以选择通过借记卡、信用卡、网上银行或货到付款进行付款。

+   第三个选项卡在选择时将提示用户输入交付地址：客户的完整地址以及州、国家和联系电话。

我们将首先更改选项卡的默认文本：

1.  使用选项卡小部件的 currentTabText 属性，更改每个选项卡按钮上显示的文本。

1.  将第一个选项卡按钮的文本属性设置为“产品列表”，将第二个选项卡按钮的文本属性设置为“付款方式”。

1.  要添加一个新的选项卡按钮，在“付款方式”选项卡上右键单击，并从出现的上下文菜单中选择“插入页面”。

1.  从出现的两个选项中，选择“当前页之后”和“当前页之前”，选择“当前页之后”以在“付款方式”选项卡之后添加一个新选项卡。新选项卡将具有默认文本“页面”。

1.  使用 currentTabText 属性，将其文本更改为“交付地址”。

1.  通过选择并拖动其节点来展开选项卡窗口，以在选项卡按钮下方提供空白空间，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/b6126880-8e88-4af4-8962-2e6c6189ab03.png)

1.  选择每个选项卡按钮，并将所需的小部件放入提供的空白空间。例如，将四个复选框小部件放到第一个选项卡按钮“产品列表”上，以显示可供销售的物品。

1.  在表单上放置一个推送按钮小部件。

1.  将四个复选框的文本属性更改为`手机$150`、`笔记本电脑$500`、`相机$250`和`鞋子$200`。

1.  将推送按钮小部件的文本属性更改为“添加到购物车”，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/b2d67f02-bf7b-429a-ab06-7126574542d3.png)

1.  类似地，要提供不同的付款方式，选择第二个选项卡，并在可用空间中放置四个单选按钮。

1.  将四个单选按钮的文本属性设置为“借记卡”、“信用卡”、“网上银行”和“货到付款”，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/4364f884-9029-4a33-8108-ea92a68f713a.png)

1.  选择第三个选项卡，然后拖放几个 LineEdit 小部件，提示用户提供交付地址。

1.  将六个 Label 和六个 LineEdit 小部件拖放到表单上。

1.  将 Label 小部件的文本属性设置为`地址 1`、`地址 2`、`州`、`国家`、`邮政编码`和`联系电话`。每个 Label 小部件前面的 LineEdit 小部件将用于获取交付地址，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/a7e83202-7705-4a75-be08-304e168d0f2a.png)

1.  将应用程序保存为`demoTabWidget.ui`。

1.  使用 Qt Designer 创建的用户界面存储在一个`.ui`文件中，这是一个 XML 文件，需要转换为 Python 代码。要进行转换，需要打开命令提示符窗口，转到保存文件的文件夹，并发出此命令：

```py
C:PythonbookPyQt5>pyuic5 demoTabWidget.ui -o demoTabWidget.py
```

生成的 Python 脚本文件`demoTabWidget.py`的代码可以在本书的源代码包中找到。通过将其导入到另一个 Python 脚本中，使用自动生成的代码`demoTablWidget.py`创建的用户界面设计。

1.  创建另一个名为`callTabWidget.pyw`的 Python 文件，并将`demoTabWidget.py`代码导入其中：

```py
import sys
from PyQt5.QtWidgets import QDialog, QApplication
from demoTabWidget import *
class MyForm(QDialog):
    def __init__(self):
        super().__init__()
        self.ui = Ui_Dialog()
        self.ui.setupUi(self)
        self.show()
if __name__=="__main__":
    app = QApplication(sys.argv)
    w = MyForm()
    w.show()
    sys.exit(app.exec_())
```

# 工作原理...

如`callTabWidget.pyw`中所示，导入了必要的模块。创建了`MyForm`类，并继承自基类`QDialog`。调用了`QDialog`的默认构造函数。

通过`QApplication()`方法创建名为`app`的应用程序对象。每个 PyQt5 应用程序都必须创建一个应用程序对象。在创建应用程序对象时，将`sys.argv`参数传递给`QApplication()`方法。`sys.argv`参数包含来自命令行的参数列表，并有助于传递和控制脚本的启动属性。之后，使用`MyForm`类的实例创建名为`w`的实例。在实例上调用`show()`方法，将在屏幕上显示小部件。`sys.exit()`方法确保干净的退出，释放内存资源。

当应用程序执行时，您会发现默认情况下选择了第一个选项卡“产品列表”，并且该选项卡中指定的可供销售的产品如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/e9c425e7-bfb5-4e0f-9260-a0fc9787747a.png)

同样，在选择其他选项卡“付款方式”和“交货地址”时，您将看到小部件提示用户选择所需的付款方式并输入交货地址。

# 创建自定义菜单栏

一个大型应用程序通常被分解为小的、独立的、可管理的模块。这些模块可以通过制作不同的工具栏按钮或菜单项来调用。也就是说，我们可以在单击菜单项时调用一个模块。我们在不同的软件包中看到了文件菜单、编辑菜单等，因此让我们学习如何制作自己的自定义菜单栏。

在本教程中，我们将学习创建显示特定菜单项的菜单栏。我们将学习如何添加菜单项，向菜单项添加子菜单项，在菜单项之间添加分隔符，向菜单项添加快捷键和工具提示，以及更多内容。我们还将学习如何向这些菜单项添加操作，以便单击任何菜单项时会执行某个操作。

我们的菜单栏将包括两个菜单，绘图和编辑。绘图菜单将包括四个菜单项，绘制圆形、绘制矩形、绘制直线和属性。属性菜单项将包括两个子菜单项，页面设置和设置密码。第二个菜单，编辑，将包括三个菜单项，剪切、复制和粘贴。让我们创建一个新应用程序，以了解如何实际创建这个菜单栏。

# 如何做…

我们将按照逐步程序来制作两个菜单，以及每个菜单中的相应菜单项。为了快速访问，每个菜单项也将与快捷键相关联。以下是创建我们自定义菜单栏的步骤：

1.  启动 Qt Designer 并创建一个基于 Main Window 模板的应用程序。

您会得到具有默认菜单栏的新应用程序，因为 Qt Designer 的 Main Window 模板默认提供了一个显示菜单栏的主应用程序窗口。默认菜单栏如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/2e3d83c2-7891-4cdd-894e-b425ca161c42.png)

1.  您可以通过右键单击主窗口并从弹出的上下文菜单中选择“删除菜单栏”选项来删除默认菜单栏。

1.  您还可以通过从上下文菜单中选择“创建菜单栏”选项来稍后添加菜单栏。

默认菜单栏包含“在此处输入”占位符。您可以用菜单项文本替换它们。

1.  单击占位符以突出显示它，并输入以修改其文本。当您添加菜单项时，“在此处输入”将出现在新菜单项下方。

1.  再次，只需单击“在此处输入”占位符以选择它，然后简单地输入下一个菜单项的文本。

1.  您可以通过右键单击任何菜单项并从弹出的上下文菜单中选择“删除操作 action_name”选项来删除任何菜单项。

菜单栏中的菜单和菜单项可以通过拖放在所需位置进行排列。

在编写菜单或菜单项文本时，如果在任何字符之前添加一个`&`字符，菜单中的该字符将显示为下划线，并且将被视为快捷键。我们还将学习如何稍后为菜单项分配快捷键。

1.  当您通过替换“在此处输入”占位符创建新菜单项时，该菜单项将显示为操作编辑框中的单独操作，您可以从那里配置其属性。

回想一下，我们想在这个菜单栏中创建两个菜单，文本为“绘图”和“编辑”。绘图菜单将包含三个菜单项，绘制圆形、绘制矩形和绘制直线。在这三个菜单项之后，将插入一个分隔符，然后是一个名为“属性”的第四个菜单项。属性菜单项将包含两个子菜单项，页面设置和设置密码。编辑菜单将包含三个菜单项，剪切、复制和粘贴。

1.  双击“在此处输入”占位符，输入第一个菜单“绘图”的文本。

在“绘图”菜单上按下箭头键会弹出“在此处输入”和“添加分隔符”选项，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/ffd03bb2-b7a0-4bfd-b06f-8ff20c3fe644.png)

1.  双击“在此处输入”，并为“绘制”菜单下的第一个菜单项输入“绘制圆形”。在“绘制圆形”菜单上按下箭头键会再次提供“在此处输入”和“添加分隔符”选项。

1.  双击“在此处输入”并输入“绘制矩形”作为菜单项。

1.  按下下箭头键以获取两个选项，“在此处输入”和“添加分隔符”。

1.  双击“在此处输入”，并为第三个菜单项输入“绘制线条”。

1.  按下下箭头键后，再次会出现两个选项，“在此处输入”和“添加分隔符”，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/3c657aa6-7475-4351-b2ec-cf8ee426cad9.png)

1.  选择“添加分隔符”以在前三个菜单项后添加分隔符。

1.  在分隔符后按下下箭头键，并添加第四个菜单项“属性”。这是因为我们希望“属性”菜单项有两个子菜单项。

1.  选择右箭头以向“属性”菜单添加子菜单项。

1.  在任何菜单项上按下右箭头键，以向其添加子菜单项。在子菜单项中，选择“在此处输入”，并输入第一个子菜单“页面设置”。

1.  选择下箭头，并在页面设置子菜单项下输入“设置密码”，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/825e7797-8b3e-40b5-a874-80eaa7cb8b7b.png)

1.  第一个菜单“绘制”已完成。现在，我们需要添加另一个菜单“编辑”。选择“绘制”菜单，并按下右箭头键，表示要在菜单栏中添加第二个菜单。

1.  将“在此处输入”替换为“编辑”。

1.  按下下箭头，并添加三个菜单项，剪切、复制和粘贴，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/7a3b7048-2461-4c44-bc0c-f8fa84ae0c48.png)

所有菜单项的操作将自动显示在操作编辑框中，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/82d0ef70-87a2-4caf-b144-188354deaddd.png)

您可以看到操作名称是通过在每个菜单文本前缀文本操作并用下划线替换空格而生成的。这些操作可用于配置菜单项。

1.  要添加悬停在任何菜单项上时出现的工具提示消息，可以使用 ToolTip 属性。

1.  要为“绘制”菜单的“绘制圆形”菜单项分配工具提示消息，请在操作编辑框中选择 actionDraw_Circle，并将 ToolTip 属性设置为“绘制圆形”。类似地，您可以为所有菜单项分配工具提示消息。

1.  要为任何菜单项分配快捷键，请从操作编辑框中打开其操作，并单击快捷方式框内。

1.  在快捷方式框中，按下要分配给所选菜单项的键组合。

例如，如果在快捷方式框中按下*Ctrl* + *C*，则如下截图所示，Ctrl+C 将出现在框中：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/6bb09b03-387a-4d7a-8c93-cf97e7cb1f01.png)

您可以使用任何组合的快捷键，例如*Shift* +键，*Alt* +键和*Ctrl* + *Shift* +键，用于任何菜单项。快捷键将自动显示在菜单栏中的菜单项中。您还可以使任何菜单项可选，即可以将其设置为切换菜单项。

1.  为此，选择所需菜单项的操作并勾选可选复选框。每个菜单项的操作，以及其操作名称、菜单文本、快捷键、可选状态和工具提示，都会显示在操作编辑框中。以下截图显示了“设置密码”子菜单项的操作，确认其快捷键为*Shift* + *P*，并且可以选择：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/f59b87e8-e715-4468-955c-e06836bb1e81.png)

1.  对于“绘制圆形”、“绘制矩形”和“绘制线条”菜单项，我们将添加代码来分别绘制圆形、矩形和直线。

1.  对于其余的菜单项，我们希望当用户选择任何一个时，在表单上会出现一个文本消息，指示选择了哪个菜单项。

1.  要显示消息，请将标签小部件拖放到表单上。

1.  我们的菜单栏已完成；使用名称`demoMenuBar.ui`保存应用程序。

1.  我们使用`pyuic5`命令行实用程序将`.ui`（XML）文件转换为 Python 代码。

生成的 Python 代码`demoMenuBar.py`可以在本书的源代码包中找到。

1.  创建一个名为`callMenuBar.pyw`的 Python 脚本，导入之前的代码`demoMenuBar.py`，以调用菜单并在选择菜单项时显示带有 Label 小部件的文本消息。

您希望出现一条消息，指示选择了哪个菜单项。此外，当选择 Draw Circle、Draw Rectangle 和 Draw Line 菜单项时，您希望分别绘制一个圆、矩形和线。Python `callMenuBar.pyw`脚本中的代码将如下屏幕截图所示：

```py
import sys
from PyQt5.QtWidgets import QMainWindow, QApplication
from PyQt5.QtGui import QPainter

from demoMenuBar import *

class AppWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.pos1 = [0,0]
        self.pos2 = [0,0]
        self.toDraw=""
        self.ui.actionDraw_Circle.triggered.connect(self.
        drawCircle)
        self.ui.actionDraw_Rectangle.triggered.connect(self.
        drawRectangle)
        self.ui.actionDraw_Line.triggered.connect(self.drawLine)
        self.ui.actionPage_Setup.triggered.connect(self.pageSetup)
        self.ui.actionSet_Password.triggered.connect(self.
        setPassword)
        self.ui.actionCut.triggered.connect(self.cutMethod)
        self.ui.actionCopy.triggered.connect(self.copyMethod)
        self.ui.actionPaste.triggered.connect(self.pasteMethod)      
        self.show()

    def paintEvent(self, event):
        qp = QPainter()
        qp.begin(self)
        if self.toDraw=="rectangle":
            width = self.pos2[0]-self.pos1[0]
            height = self.pos2[1] - self.pos1[1]    
            qp.drawRect(self.pos1[0], self.pos1[1], width, height)
        if self.toDraw=="line":
            qp.drawLine(self.pos1[0], self.pos1[1], self.pos2[0], 
            self.pos2[1])
        if self.toDraw=="circle":
            width = self.pos2[0]-self.pos1[0]
            height = self.pos2[1] - self.pos1[1]           
            rect = QtCore.QRect(self.pos1[0], self.pos1[1], width,
            height)
            startAngle = 0
            arcLength = 360 *16
            qp.drawArc(rect, startAngle, 
            arcLength)     
        qp.end()

    def mousePressEvent(self, event):
        if event.buttons() & QtCore.Qt.LeftButton:
            self.pos1[0], self.pos1[1] = event.pos().x(), 
            event.pos().y()

    def mouseReleaseEvent(self, event):
        self.pos2[0], self.pos2[1] = event.pos().x(), 
        event.pos().y()   
        self.update()

    def drawCircle(self):
        self.ui.label.setText("")
        self.toDraw="circle"

    def drawRectangle(self):
        self.ui.label.setText("")
        self.toDraw="rectangle"

    def drawLine(self):
        self.ui.label.setText("")
        self.toDraw="line"

    def pageSetup(self):
        self.ui.label.setText("Page Setup menu item is selected")

    def setPassword(self):
        self.ui.label.setText("Set Password menu item is selected")

    def cutMethod(self):
        self.ui.label.setText("Cut menu item is selected")

    def copyMethod(self):
        self.ui.label.setText("Copy menu item is selected")

    def pasteMethod(self):
        self.ui.label.setText("Paste menu item is selected")

app = QApplication(sys.argv)
w = AppWindow()
w.show()
sys.exit(app.exec_())
```

# 工作原理... 

每个菜单项的操作的 triggered()信号都连接到其相应的方法。每个菜单项的 triggered()信号都连接到`drawCircle()`方法，因此每当从菜单栏中选择 Draw Circle 菜单项时，都会调用`drawCircle()`方法。类似地，actionDraw_Rectangle 和 actionDraw_Line 菜单的 triggered()信号分别连接到`drawRectangle()`和`drawLine()`方法。在`drawCircle()`方法中，`toDraw`变量被分配一个字符串`circle`。`toDraw`变量将用于确定在`paintEvent`方法中要绘制的图形。`toDraw`变量可以分配三个字符串中的任何一个，即`line`、`circle`或`rectangle`。对`toDraw`变量中的值应用条件分支，相应地将调用绘制线条、矩形或圆的方法。图形将根据鼠标确定的大小进行绘制，即用户需要单击鼠标并拖动以确定图形的大小。

两种方法，`mousePressEvent()`和`mouseReleaseEvent()`，在按下和释放左鼠标按钮时会自动调用。为了存储按下和释放左鼠标按钮的位置的`x`和`y`坐标，使用了两个数组`pos1`和`pos2`。左鼠标按钮按下和释放的位置的`x`和`y`坐标值通过`mousePressEvent`和`mouseReleaseEvent`方法分配给`pos1`和`pos2`数组。

在`mouseReleaseEvent`方法中，分配鼠标释放位置的`x`和`y`坐标值后，调用`self.update`方法来调用`paintEvent()`方法。在`paintEvent()`方法中，基于分配给`toDraw`变量的字符串进行分支。如果`toDraw`变量分配了`line`字符串，`QPainter`类将通过`drawLine()`方法来绘制两个鼠标位置之间的线。类似地，如果`toDraw`变量分配了`circle`字符串，`QPainter`类将通过`drawArc()`方法来绘制直径由鼠标位置提供的圆。如果`toDraw`变量分配了`rectangle`字符串，`QPainter`类将通过`drawRect()`方法来绘制由鼠标位置提供的宽度和高度的矩形。

除了三个菜单项 Draw Circle、Draw Rectangle 和 Draw Line 之外，如果用户单击任何其他菜单项，将显示一条消息，指示用户单击的菜单项。因此，其余菜单项的 triggered()信号将连接到显示用户通过 Label 小部件选择的菜单项的消息信息的方法。

运行应用程序时，您会发现一个带有两个菜单 Draw 和 Edit 的菜单栏。Draw 菜单将显示四个菜单项 Draw Circle、Draw Rectangle、Draw Line 和 Properties，在 Properties 菜单项之前显示一个分隔符。Properties 菜单项显示两个子菜单项 Page Setup 和 Set Password，以及它们的快捷键，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/de30b61b-0eec-478b-9087-8742218d3ff2.png)

绘制一个圆，点击“绘制圆”菜单项，在窗体上的某个位置点击鼠标按钮，保持鼠标按钮按住，拖动以定义圆的直径。释放鼠标按钮时，将在鼠标按下和释放的位置之间绘制一个圆，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/84c641ca-4c5c-4551-adf5-3fda193607ee.png)

选择其他菜单项时，将显示一条消息，指示按下的菜单项。例如，选择“复制”菜单项时，将显示消息“选择了复制菜单项”，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/a080f906-4107-4d99-bc5b-3206026fb4fa.png)
