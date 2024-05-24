# Python GUI 编程（七）

> 原文：[`zh.annas-archive.org/md5/9d5f7126bd532a80dd6a9dce44175aaa`](https://zh.annas-archive.org/md5/9d5f7126bd532a80dd6a9dce44175aaa)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十九章：数据库处理

数据库处理在任何应用程序中都起着重要作用，因为数据需要存储以备将来使用。您需要存储客户信息、用户信息、产品信息、订单信息等。在本章中，您将学习与数据库处理相关的每项任务：

+   创建数据库

+   创建数据库表

+   在指定的数据库表中插入行

+   显示指定数据库表中的行

+   在指定的数据库表中导航行

+   在数据库表中搜索特定信息

+   创建登录表单-应用认证程序

+   更新数据库表-更改用户密码

+   从数据库表中删除一行

我们将使用 SQLite 进行数据库处理。在我们进入本章的更深入之前，让我们快速介绍一下 SQLite。

# 介绍

SQLite 是一个非常易于使用的数据库引擎。基本上，它是一个轻量级数据库，适用于存储在单个磁盘文件中的小型应用程序。它是一个非常受欢迎的数据库，用于手机、平板电脑、小型设备和仪器。SQLite 不需要单独的服务器进程，甚至不需要任何配置。

为了使这个数据库在 Python 脚本中更容易使用，Python 标准库包括一个名为`sqlite3`的模块。因此，要在任何 Python 应用程序中使用 SQLite，您需要使用`import`语句导入`sqlite3`模块，如下所示：

```py
import sqlite3
```

使用任何数据库的第一步是创建一个`connect`对象，通过它您需要与数据库建立连接。以下示例建立到`ECommerce`数据库的连接：

```py
conn = sqlite3.connect('ECommerce.db')
```

如果数据库已经存在，此示例将建立到`ECommerce`数据库的连接。如果数据库不存在，则首先创建数据库，然后建立连接。

您还可以使用`connect`方法中的`:memory:`参数在内存中创建临时数据库。

```py
conn = sqlite3.connect(':memory:')
```

您还可以使用`:memory:`特殊名称在 RAM 中创建数据库。

一旦与数据库相关的工作结束，您需要使用以下语句关闭连接：

```py
conn.close()
```

# 创建游标对象

要使用数据库表，您需要获取一个`cursor`对象，并将 SQL 语句传递给`cursor`对象以执行它们。以下语句创建一个名为`cur`的`cursor`对象：

```py
cur = conn.cursor()
```

使用`cursor`对象`cur`，您可以执行 SQL 语句。例如，以下一组语句创建一个包含三列`id`、`EmailAddress`和`Password`的`Users`表：

```py
# Get a cursor object
cur = conn.cursor() cur.execute('''CREATE TABLE Users(id INTEGER PRIMARY KEY, EmailAddress TEXT, Password TEXT)''') conn.commit()
```

请记住，您需要通过在连接对象上调用`commit()`方法来提交对数据库的更改，否则对数据库所做的所有更改都将丢失。

以下一组语句将删除`Users`表：

```py
# Get a cursor object
cur = conn.cursor() cur.execute('''DROP TABLE Users''') conn.commit()
```

# 创建数据库

在这个示例中，我们将提示用户输入数据库名称，然后点击按钮。点击按钮后，如果指定的数据库不存在，则创建它，如果已经存在，则连接它。

# 如何做…

按照逐步过程在 SQLite 中创建数据库：

1.  让我们基于没有按钮的对话框模板创建一个应用程序。

1.  通过拖放两个标签小部件、一个行编辑小部件和一个按钮小部件到表单上，添加两个`QLabel`小部件、一个`QLineEdit`小部件和一个`QPushButton`小部件。

1.  将第一个标签小部件的文本属性设置为`输入数据库名称`。

1.  删除第二个标签小部件的文本属性，因为这是已经建立的。

1.  将行编辑小部件的对象名称属性设置为`lineEditDBName`。

1.  将按钮小部件的对象名称属性设置为`pushButtonCreateDB`。

1.  将第二个标签小部件的对象名称属性设置为`labelResponse`。

1.  将应用程序保存为`demoDatabase.ui`。表单现在将显示如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/14fd5deb-fdad-4905-8ce4-b20927514f75.png)

使用 Qt Designer 创建的用户界面存储在`.ui`文件中，这是一个 XML 文件，需要转换为 Python 代码。通过应用`pyuic5`实用程序，将 XML 文件转换为 Python 代码。生成的 Python 脚本`demoDatabase.py`可以在本书的源代码包中看到。

1.  将`demoDatabase.py`脚本视为头文件，并将其导入到将调用其用户界面设计的文件中。

1.  创建另一个名为`callDatabase.pyw`的 Python 文件，并将`demoDatabase.py`代码导入其中：

```py
import sqlite3, sys
from PyQt5.QtWidgets import QDialog, QApplication
from sqlite3 import Error
from demoDatabase import *
class MyForm(QDialog):
    def __init__(self):
        super().__init__()
        self.ui = Ui_Dialog()
        self.ui.setupUi(self)
        self.ui.pushButtonCreateDB.clicked.connect(self.
        createDatabase)
        self.show()
    def createDatabase(self):
        try:
            conn = sqlite3.connect(self.ui.lineEditDBName.
            text()+".db")
            self.ui.labelResponse.setText("Database is created")
        except Error as e:
            self.ui.labelResponse.setText("Some error has 
            occurred")
        finally:
            conn.close()
if __name__=="__main__":
    app = QApplication(sys.argv)
    w = MyForm()
    w.show()
    sys.exit(app.exec_())
```

# 它是如何工作的...

您可以在脚本中看到，具有 objectName 属性`pushButtonCreateDB`的按钮的 click()事件与`createDatabase()`方法连接在一起。这意味着每当单击按钮时，就会调用`createDatabase()`方法。在`createDatabase()`方法中，调用了`sqlite3`类的`connect()`方法，并将用户在 Line Edit 小部件中输入的数据库名称传递给`connect()`方法。如果在创建数据库时没有发生错误，则通过 Label 小部件显示消息“数据库已创建”以通知用户；否则，通过 Label 小部件显示消息“发生了一些错误”以指示发生错误。

运行应用程序时，将提示您输入数据库名称。假设我们输入数据库名称为`Ecommerce`。单击“创建数据库”按钮后，将创建数据库并收到消息“数据库已创建”：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/6f1378e9-e4d2-44b9-ae9b-4d586e8ebc92.png)

# 创建数据库表

在这个示例中，我们将学习如何创建一个数据库表。用户将被提示指定数据库名称，然后是要创建的表名称。该示例使您能够输入列名及其数据类型。单击按钮后，将在指定的数据库中创建具有定义列的表。

# 如何做...

以下是创建一个 GUI 的步骤，使用户能够输入有关要创建的数据库表的所有信息。使用此 GUI，用户可以指定数据库名称、列名，并且还可以选择列类型：

1.  让我们基于没有按钮的对话框模板创建一个应用程序。

1.  通过拖放五个 Label、三个 Line Edit、一个 Combo Box 和两个 Push Button 小部件到表单上，添加五个 QLabel、三个 QLineEdit、一个 QComboBox 和两个 QPushButton 小部件。

1.  将前四个 Label 小部件的文本属性设置为`输入数据库名称`，`输入表名称`，`列名`和`数据类型`。

1.  删除第五个 Label 小部件的文本属性，因为这是通过代码建立的。

1.  将两个 push 按钮的文本属性设置为`添加列`和`创建表`。

1.  将三个 Line Edit 小部件的 objectName 属性设置为`lineEditDBName`、`lineEditTableName`和`lineEditColumnName`。

1.  将 Combo Box 小部件的 objectName 属性设置为`ComboBoxDataType`。

1.  将两个 push 按钮的 objectName 属性设置为`pushButtonAddColumn`和`pushButtonCreateTable`。

1.  将第五个 Label 小部件的 objectName 属性设置为`labelResponse`。

1.  将应用程序保存为`demoCreateTable.ui`。表单现在将显示如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/25a283f1-b10b-41da-a13d-ba1d67c4ae55.png)

使用 Qt Designer 创建的用户界面存储在`.ui`文件中，这是一个 XML 文件，需要转换为 Python 代码。使用`pyuic5`命令将 XML 文件转换为 Python 代码。本书的源代码包中可以看到生成的 Python 脚本`demoCreateTable.py`。

1.  将`demoCreateTable.py`脚本视为头文件，并将其导入到将调用其用户界面设计的文件中。

1.  创建另一个名为`callCreateTable.pyw`的 Python 文件，并将`demoCreateTable.py`代码导入其中：

```py
import sqlite3, sys
from PyQt5.QtWidgets import QDialog, QApplication
from sqlite3 import Error
from demoCreateTable import *
tabledefinition=""
class MyForm(QDialog):
    def __init__(self):
        super().__init__()
        self.ui = Ui_Dialog()
        self.ui.setupUi(self)
        self.ui.pushButtonCreateTable.clicked.connect( 
        self.createTable)
        self.ui.pushButtonAddColumn.clicked.connect(self.
        addColumns)
        self.show()
    def addColumns(self):
        global tabledefinition
        if tabledefinition=="":
            tabledefinition="CREATE TABLE IF NOT EXISTS "+   
            self.ui.lineEditTableName.text()+" ("+ 
            self.ui.lineEditColumnName.text()+"  "+                                                                                                                      
            self.ui.comboBoxDataType.itemText(self.ui.
            comboBoxDataType.currentIndex())
        else:
            tabledefinition+=","+self.ui.lineEditColumnName
            .text()+" "+ self.ui.comboBoxDataType.itemText
            (self.ui.comboBoxDataType.currentIndex())
            self.ui.lineEditColumnName.setText("")
            self.ui.lineEditColumnName.setFocus()
    def createTable(self):
        global tabledefinition
        try:
            conn = sqlite3.connect(self.ui.lineEditDBName.
            text()+".db")
            self.ui.labelResponse.setText("Database is    
            connected")
            c = conn.cursor()
            tabledefinition+=");"
            c.execute(tabledefinition)
            self.ui.labelResponse.setText("Table is successfully  
            created")
        except Error as e:
            self.ui.labelResponse.setText("Error in creating 
            table")
        finally:
            conn.close()
if __name__=="__main__":
    app = QApplication(sys.argv)
    w = MyForm()
    w.show()
    sys.exit(app.exec_())
```

# 工作原理…

在脚本中可以看到，具有 objectName 属性`pushButtonCreateTable`的按钮的 click()事件与`createTable()`方法相连。这意味着每当单击此按钮时，将调用`createTable()`方法。类似地，具有 objectName 属性`pushButtonAddColumn`的按钮的 click()事件与`addColumns()`方法相连。也就是说，单击此按钮将调用`addColumns()`方法。

在`addColumns()`方法中，定义了`CREATE TABLE SQL`语句，其中包括在 LineEdit 小部件中输入的列名和从组合框中选择的数据类型。用户可以向表中添加任意数量的列。

在`createTable()`方法中，首先建立与数据库的连接，然后执行`addColumns()`方法中定义的`CREATE TABLE SQL`语句。如果成功创建表，将通过最后一个 Label 小部件显示一条消息，通知您表已成功创建。最后，关闭与数据库的连接。

运行应用程序时，将提示您输入要创建的数据库名称和表名称，然后输入该表中所需的列。假设您要在`ECommerce`表中创建一个`Users`表，其中包括`EmailAddress`和`Password`两列，这两列都假定为文本类型。

`Users`表中的第一列名为`Email Address`，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/e6805d8b-ee5e-45dd-9d1b-f32c6aa86b7b.png)

让我们在`Users`表中定义另一列，称为`Password`，类型为文本，然后点击 Create Table 按钮。如果成功创建了指定列数的表，将通过最后一个 Label 小部件显示消息“表已成功创建”，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/37ac3783-9136-42eb-a3d5-cefc0d2d003f.png)

为了验证表是否已创建，我将使用一种可视化工具，该工具可以让您创建、编辑和查看数据库表及其中的行。这个可视化工具是 SQLite 的 DB Browser，我从[`sqlitebrowser.org/`](http://sqlitebrowser.org/)下载了它。在启动 DB Browser for SQLite 后，点击主菜单下方的“打开数据库”选项卡。浏览并选择当前文件夹中的`ECommerce`数据库。`ECommerce`数据库显示了一个包含两列`EmailAddress`和`Password`的`Users`表，如下面的屏幕截图所示，证实数据库表已成功创建：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/e64bbee5-b2a2-4f18-b53f-ee14777e310e.png)

# 在指定的数据库表中插入行

在本教程中，我们将学习如何向表中插入行。我们假设一个名为`Users`的表已经存在于名为`ECommerce`的数据库中，包含两列`EmailAddress`和`Password`。

在分别输入电子邮件地址和密码后，当用户点击“插入行”按钮时，将会将行插入到指定的数据库表中。

# 操作步骤…

以下是向存在于 SQLite 中的数据库表中插入行的步骤：

1.  让我们创建一个基于无按钮对话框模板的应用程序。

1.  通过拖放五个 Label 小部件、四个 LineEdit 小部件和一个 PushButton 小部件将它们添加到表单中。

1.  将前四个 Label 小部件的文本属性设置为“输入数据库名称”、“输入表名称”、“电子邮件地址”和“密码”。

1.  删除第五个 Label 小部件的文本属性，这是通过代码建立的。

1.  将按钮的文本属性设置为“插入行”。

1.  将四个 Line Edit 小部件的 objectName 属性设置为`lineEditDBName`、`lineEditTableName`、`lineEditEmailAddress`和`lineEditPassword`。

1.  将 Push Button 小部件的 objectName 属性设置为`pushButtonInsertRow`。

1.  将第五个 Label 小部件的 objectName 属性设置为`labelResponse`。由于我们不希望密码显示出来，我们希望用户输入密码时显示星号。

1.  为此，选择用于输入密码的 Line Edit 小部件，并从 Property Editor 窗口中选择 echoMode 属性，并将其设置为 Password，而不是默认的 Normal，如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/24010fe7-0bcd-490a-bdbf-82206bfbc3a2.png)

echoMode 属性显示以下四个选项：

+   +   Normal: 这是默认属性，当在 Line Edit 小部件中键入字符时显示。

+   NoEcho: 在 Line Edit 小部件中键入时不显示任何内容，也就是说，您甚至不会知道输入的文本长度。

+   Password: 主要用于密码。在 Line Edit 小部件中键入时显示星号。

+   PasswordEchoOnEdit: 在 Line Edit 小部件中键入密码时显示密码，尽管输入的内容会很快被星号替换。

1.  将应用程序保存为`demoInsertRowsInTable.ui`。表单现在将显示如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/e1494e00-f106-4262-91bb-46543a2899ad.png)

使用 Qt Designer 创建的用户界面存储在`.ui`文件中，这是一个 XML 文件，需要转换为 Python 代码。通过应用`pyuic5`实用程序，XML 文件将被转换为 Python 代码。生成的 Python 脚本`demoInsertRowsInTable.py`可以在本书的源代码包中找到。

1.  创建另一个名为`callInsertRows.pyw`的 Python 文件，并将`demoInsertRowsInTable.py`代码导入其中。Python 脚本`callInsertRows.pyw`中的代码如下所示：

```py
import sqlite3, sys
from PyQt5.QtWidgets import QDialog, QApplication
from sqlite3 import Error
from demoInsertRowsInTable import *
class MyForm(QDialog):
    def __init__(self):
        super().__init__()
        self.ui = Ui_Dialog()
        self.ui.setupUi(self)
        self.ui.pushButtonInsertRow.clicked.connect(self.
        InsertRows)
        self.show()
    def InsertRows(self):
        sqlStatement="INSERT INTO "+  
        self.ui.lineEditTableName.text() +"   
        VALUES('"+self.ui.lineEditEmailAddress.text()+"', 
        '"+self.ui.lineEditPassword.text()+"')"
        try:
            conn = sqlite3.connect(self.ui.lineEditDBName.
            text()+ ".db")
        with conn:
            cur = conn.cursor()
            cur.execute(sqlStatement)
            self.ui.labelResponse.setText("Row successfully 
            inserted")
        except Error as e:
            self.ui.labelResponse.setText("Error in inserting  
            row")
        finally:
            conn.close()
if __name__=="__main__":
    app = QApplication(sys.argv)
    w = MyForm()
    w.show()
    sys.exit(app.exec_())
```

# 它是如何工作的...

您可以在脚本中看到，具有 objectName 属性`pushButtonInsertRow`的 push 按钮的单击事件连接到`InsertRows()`方法。这意味着每当单击此 push 按钮时，将调用`InsertRows()`方法。在`InsertRows()`方法中，定义了一个`INSERT SQL`语句，用于获取在 Line Edit 小部件中输入的电子邮件地址和密码。与输入数据库名称的 Line Edit 小部件建立连接。然后，执行`INSERT SQL`语句，将新行添加到指定的数据库表中。最后，关闭与数据库的连接。

运行应用程序时，将提示您指定数据库名称、表名称以及两个列`Email Address`和`Password`的数据。输入所需信息后，单击插入行按钮，将向表中添加新行，并显示消息“成功插入行”，如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/69102eea-f463-4a74-9b7e-45251474e952.png)

为了验证行是否插入了`Users`表，我将使用一个名为 DB Browser for SQLite 的可视化工具。这是一个很棒的工具，可以让您创建、编辑和查看数据库表及其中的行。您可以从[`sqlitebrowser.org/`](http://sqlitebrowser.org/)下载 DB Browser for SQLite。启动 DB Browser for SQLite 后，您需要首先打开数据库。要这样做，请单击主菜单下方的打开数据库选项卡。浏览并选择当前文件夹中的`Ecommerce`数据库。`Ecommerce`数据库显示`Users`表。单击执行 SQL 按钮；您会得到一个小窗口来输入 SQL 语句。编写一个 SQL 语句，`select * from Users`，然后单击窗口上方的运行图标。

在`Users`表中输入的所有行将以表格格式显示，如下屏幕截图所示。确认我们在本教程中制作的应用程序运行良好：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/1a25fa44-24c3-4eec-9392-3540580713b0.png)

# 在指定的数据库表中显示行

在这个示例中，我们将学习从给定数据库表中获取行并通过表小部件以表格格式显示它们。我们假设一个名为`Users`的表包含两列，`EmailAddress`和`Password`，已经存在于名为`ECommerce`的数据库中。此外，我们假设`Users`表中包含一些行。

# 如何做…

按照以下逐步过程访问 SQLite 数据库表中的行：

1.  让我们基于没有按钮的对话框模板创建一个应用程序。

1.  通过拖放三个标签小部件、两个行编辑小部件、一个按钮和一个表小部件到表单上，向表单添加三个`QLabel`小部件、两个`QLineEdit`小部件、一个`QPushButton`小部件和一个`QTableWidget`小部件。

1.  将两个标签小部件的文本属性设置为`输入数据库名称`和`输入表名称`。

1.  删除第三个标签小部件的文本属性，因为它的文本属性将通过代码设置。

1.  将按钮的文本属性设置为`显示行`。

1.  将两个行编辑小部件的 objectName 属性设置为`lineEditDBName`和`lineEditTableName`。

1.  将按钮小部件的 objectName 属性设置为`pushButtonDisplayRows`。

1.  将第三个标签小部件的 objectName 属性设置为`labelResponse`。

1.  将应用程序保存为`demoDisplayRowsOfTable.ui`。表单现在将显示如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/087f96d5-d68f-46ed-b734-460c08612c8e.png)

将通过表小部件显示的`Users`表包含两列。

1.  选择表小部件，并在属性编辑器窗口中选择其 columnCount 属性。

1.  将 columnCount 属性设置为`2`，将 rowCount 属性设置为`3`，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/546d14f3-3cac-43df-81dd-b36542f6cc78.png)

使用 Qt Designer 创建的用户界面存储在`.ui`文件中，这是一个 XML 文件，需要转换为 Python 代码。通过应用`pyuic5`实用程序，XML 文件将被转换为 Python 代码。生成的 Python 脚本`demoInsertRowsInTable.py`可以在本书的源代码包中找到。

1.  将`demoInsertRowsInTable.py`脚本视为头文件，并将其导入到将调用其用户界面设计的文件中。

1.  创建另一个名为`callDisplayRows.pyw`的 Python 文件，并将`demoDisplayRowsOfTable.py`代码导入其中：

```py
import sqlite3, sys
from PyQt5.QtWidgets import QDialog, QApplication,QTableWidgetItem
from sqlite3 import Error
from demoDisplayRowsOfTable import *
class MyForm(QDialog):
    def __init__(self):
        super().__init__()
        self.ui = Ui_Dialog()
        self.ui.setupUi(self)
        self.ui.pushButtonDisplayRows.clicked. 
            connect(self.DisplayRows)
        self.show()

    def DisplayRows(self):
        sqlStatement="SELECT * FROM "+ 
            self.ui.lineEditTableName.text()
        try:
            conn = sqlite3.connect(self.ui.lineEditDBName.
            text()+ ".db")
            cur = conn.cursor()
            cur.execute(sqlStatement)
            rows = cur.fetchall()
            rowNo=0
        for tuple in rows:
            self.ui.labelResponse.setText("")
            colNo=0
        for columns in tuple:
            oneColumn=QTableWidgetItem(columns)
            self.ui.tableWidget.setItem(rowNo, colNo, oneColumn)
            colNo+=1
            rowNo+=1
        except Error as e:
            self.ui.tableWidget.clear()
            self.ui.labelResponse.setText("Error in accessing  
            table")
        finally:
            conn.close()
if __name__=="__main__":
    app = QApplication(sys.argv)
    w = MyForm()
    w.show()
    sys.exit(app.exec_())
```

# 工作原理…

您可以在脚本中看到，按钮的 click()事件与 objectName 属性`pushButtonDisplayRows`连接到`DisplayRows()`方法。这意味着每当单击此按钮时，将调用`DisplayRows()`方法。在`DisplayRows()`方法中，定义了一个`SQL SELECT`语句，该语句从在行编辑小部件中指定的表中获取行。还与在行编辑小部件中输入的数据库名称建立了连接。然后执行`SQL SELECT`语句。在光标上执行`fetchall()`方法，以保留从数据库表中访问的所有行。

执行`for`循环以一次访问接收到的行中的一个元组，并再次在元组上执行`for`循环以获取该行中每一列的数据。在表小部件中显示分配给行每一列的数据。在显示第一行的数据后，从行中选择第二行，并重复该过程以在表小部件中显示第二行的数据。两个嵌套的`for`循环一直执行，直到通过表小部件显示所有行。

运行应用程序时，您将被提示指定数据库名称和表名。输入所需信息后，单击“显示行”按钮，指定数据库表的内容将通过表部件显示，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/5e0fe826-4244-4c96-8cde-7e30a582d172.png)

# 浏览指定数据库表的行

在本教程中，我们将学习逐个从给定数据库表中获取行。也就是说，运行应用程序时，将显示数据库表的第一行。应用程序中提供了四个按钮，称为 Next、Previous、First 和 Last。顾名思义，单击 Next 按钮将显示序列中的下一行。类似地，单击 Previous 按钮将显示序列中的上一行。单击 Last 按钮将显示数据库表的最后一行，单击 First 按钮将显示数据库表的第一行。

# 如何做…

以下是了解如何逐个访问和显示数据库表中的行的步骤：

1.  让我们基于没有按钮的对话框模板创建一个应用程序。

1.  通过拖放三个标签部件、两个行编辑部件和四个按钮部件将它们添加到表单上。

1.  将两个标签部件的文本属性设置为`Email Address`和`Password`。

1.  删除第三个标签部件的文本属性，因为它的文本属性将通过代码设置。

1.  将四个按钮的文本属性设置为`First Row`、`Previous`、`Next`和`Last Row`。

1.  将两个行编辑部件的 objectName 属性设置为`lineEditEmailAddress`和`lineEditPassword`。

1.  将四个按钮的 objectName 属性设置为`pushButtonFirst`、`pushButtonPrevious`、`pushButtonNext`和`pushButtonLast`。

1.  将第三个标签部件的 objectName 属性设置为`labelResponse`。因为我们不希望密码被显示，我们希望用户输入密码时出现星号。

1.  选择用于输入密码的行编辑部件（lineEditPassword），从属性编辑器窗口中选择 echoMode 属性，并将其设置为 Password，而不是默认的 Normal。

1.  将应用程序保存为`demoShowRecords`。表单现在将显示如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/2a4ab6c3-609c-4fd9-96b0-b375a38941dd.png)

使用 Qt Designer 创建的用户界面存储在`.ui`文件中，这是一个 XML 文件，应用`pyuic5`命令后，XML 文件可以转换为 Python 代码。书籍的源代码包中可以看到生成的 Python 脚本`demoShowRecords.py`。

1.  将`demoShowRecords.py`脚本视为头文件，并将其导入到将调用其用户界面设计的文件中。

1.  创建另一个名为`callShowRecords.pyw`的 Python 文件，并将`demoShowRecords.py`代码导入其中。

```py
import sqlite3, sys
from PyQt5.QtWidgets import QDialog, QApplication,QTableWidgetItem
from sqlite3 import Error
from demoShowRecords import *
rowNo=1
sqlStatement="SELECT EmailAddress, Password FROM Users"
conn = sqlite3.connect("ECommerce.db")
cur = conn.cursor()
class MyForm(QDialog):
    def __init__(self):
        super().__init__()
        self.ui = Ui_Dialog()
        self.ui.setupUi(self)
        cur.execute(sqlStatement)
        self.ui.pushButtonFirst.clicked.connect(self.
        ShowFirstRow)
        self.ui.pushButtonPrevious.clicked.connect(self.
        ShowPreviousRow)
        self.ui.pushButtonNext.clicked.connect(self.ShowNextRow)
        self.ui.pushButtonLast.clicked.connect(self.ShowLastRow)
        self.show()
    def ShowFirstRow(self):
        try:
            cur.execute(sqlStatement)
            row=cur.fetchone()
        if row:
            self.ui.lineEditEmailAddress.setText(row[0])
            self.ui.lineEditPassword.setText(row[1])
        except Error as e:
            self.ui.labelResponse.setText("Error in accessing  
            table")
    def ShowPreviousRow(self):
        global rowNo
        rowNo -= 1
        sqlStatement="SELECT EmailAddress, Password FROM Users  
        where rowid="+str(rowNo)
        cur.execute(sqlStatement)
        row=cur.fetchone()
        if row: 
            self.ui.labelResponse.setText("")
            self.ui.lineEditEmailAddress.setText(row[0])
            self.ui.lineEditPassword.setText(row[1])
        else:
            rowNo += 1
            self.ui.labelResponse.setText("This is the first  
            row")
        def ShowNextRow(self):
            global rowNo
            rowNo += 1
            sqlStatement="SELECT EmailAddress, Password FROM  
            Users where rowid="+str(rowNo)
            cur.execute(sqlStatement)
            row=cur.fetchone()
            if row:
                self.ui.labelResponse.setText("")
                self.ui.lineEditEmailAddress.setText(row[0])
                self.ui.lineEditPassword.setText(row[1])
            else:
                rowNo -= 1
                self.ui.labelResponse.setText("This is the last  
                row")
    def ShowLastRow(self):
        cur.execute(sqlStatement)
        for row in cur.fetchall():
            self.ui.lineEditEmailAddress.setText(row[0])
            self.ui.lineEditPassword.setText(row[1])
if __name__=="__main__":
    app = QApplication(sys.argv)
    w = MyForm()
    w.show()
    sys.exit(app.exec_())
```

# 它是如何工作的…

您可以在脚本中看到，具有 objectName 属性`pushButtonFirst`的按钮的 click()事件连接到`ShowFirstRow()`方法，具有 objectName 属性`pushButtonPrevious`的按钮连接到`ShowPreviousRow()`方法，具有 objectName 属性`pushButtonNext`的按钮连接到`ShowNextRow()`方法，具有 objectName 属性`pushButtonLast`的按钮连接到`ShowLastRow()`方法。

每当单击按钮时，将调用相关方法。

在`ShowFirstRow()`方法中，执行了一个`SQL SELECT`语句，获取了`Users`表的电子邮件地址和密码列。在光标上执行了`fetchone()`方法，以访问执行`SQL SELECT`语句后接收到的第一行。`EmailAddress`和`Password`列中的数据通过屏幕上的两个 Line Edit 小部件显示出来。如果在访问行时发生错误，错误消息`Error in accessing table`将通过标签小部件显示出来。

为了获取上一行，我们使用了一个全局变量`rowNo`，它被初始化为`1`。在`ShowPreviousRow()`方法中，全局变量`rowNo`的值减少了`1`。然后，执行了一个`SQL SELECT`语句，获取了`Users`表的`EmailAddress`和`Password`列，其中`rowid=rowNo`。因为`rowNo`变量减少了`1`，所以`SQL SELECT`语句将获取序列中的上一行。在光标上执行了`fetchone()`方法，以访问接收到的行，`EmailAddress`和`Password`列中的数据通过屏幕上的两个 Line Edit 小部件显示出来。

如果已经显示了第一行，则点击“上一个”按钮，它将通过标签小部件简单地显示消息“This is the first row”。

在访问序列中的下一行时，我们使用全局变量`rowNo`。在`ShowNextRow()`方法中，全局变量`rowNo`的值增加了`1`。然后，执行了一个`SQL SELECT`语句，获取了`Users`表的`EmailAddress`和`Password`列，其中`rowid=rowNo`；因此，访问了下一行，即`rowid`比当前行高`1`的行。在光标上执行了`fetchone()`方法，以访问接收到的行，`EmailAddress`和`Password`列中的数据通过屏幕上的两个 Line Edit 小部件显示出来。

如果您正在查看数据库表中的最后一行，然后点击“下一个”按钮，它将通过标签小部件简单地显示消息“This is the last row”。

在`ShowLastRow()`方法中，执行了一个`SQL SELECT`语句，获取了`Users`表的`EmailAddress`和`Password`列。在光标上执行了`fetchall()`方法，以访问数据库表中其余的行。使用`for`循环，将`row`变量从执行`SQL SELECT`语句后接收到的行中移动到最后一行。最后一行的`EmailAddress`和`Password`列中的数据通过屏幕上的两个 Line Edit 小部件显示出来。

运行应用程序后，您将在屏幕上看到数据库表的第一行，如下截图所示。如果现在点击“上一个”按钮，您将收到消息“This is the first row”。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/ab778559-635d-4314-b72e-c2ae0545b23f.png)

点击“下一个”按钮后，序列中的下一行将显示在屏幕上，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/e9aadf57-6616-4a5a-89c4-10a602b9eb67.png)

点击“最后一行”按钮后，数据库表中的最后一行将显示出来，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/a7f26b14-4a30-43ca-b31e-1f9b7aeebb8a.png)

# 搜索数据库表中的特定信息

在这个示例中，我们将学习如何在数据库表中执行搜索，以获取所需的信息。我们假设用户忘记了他们的密码。因此，您将被提示输入数据库名称、表名称和需要密码的用户的电子邮件地址。如果数据库表中存在使用提供的电子邮件地址的用户，则将搜索、访问并在屏幕上显示该用户的密码。

# 如何做…

按照以下步骤了解如何在 SQLite 数据库表中搜索数据：

1.  让我们基于没有按钮的对话框模板创建一个应用程序。

1.  通过拖放五个 Label 小部件、四个 LineEdit 小部件和一个 PushButton 小部件到表单上，向表单添加五个`QLabel`小部件、四个`QLineEdit`小部件和一个`QPushButton`小部件。

1.  将前三个 Label 小部件的文本属性设置为`输入数据库名称`、`输入表名称`和`电子邮件地址`。

1.  删除第四个 Label 小部件的文本属性，这是通过代码建立的。

1.  将第五个 Label 小部件的文本属性设置为`Password`。

1.  将 PushButton 的文本属性设置为`搜索`。

1.  将四个 LineEdit 小部件的 objectName 属性设置为`lineEditDBName`、`lineEditTableName`、`lineEditEmailAddress`和`lineEditPassword`。

1.  将 PushButton 小部件的 objectName 属性设置为`pushButtonSearch`。

1.  将第四个 Label 小部件的 objectName 属性设置为`labelResponse`。

1.  将应用程序保存为`demoSearchRows.ui`。表单现在将显示如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/3809324e-2973-4898-b19b-678430a5da8a.png)

使用 Qt Designer 创建的用户界面存储在一个`.ui`文件中，这是一个需要通过`pyuic5`命令应用转换为 Python 代码的 XML 文件。书籍的源代码包中可以看到生成的 Python 脚本`demoSearchRows.py`。

1.  将`demoSearchRows.py`脚本视为头文件，并将其导入到您将调用其用户界面设计的文件中。

1.  创建另一个名为`callSearchRows.pyw`的 Python 文件，并将`demoSearchRows.py`代码导入其中：

```py
import sqlite3, sys
from PyQt5.QtWidgets import QDialog, QApplication
from sqlite3 import Error
from demoSearchRows import *
class MyForm(QDialog):
    def __init__(self):
        super().__init__()
        self.ui = Ui_Dialog()
        self.ui.setupUi(self)
        self.ui.pushButtonSearch.clicked.connect(self.
        SearchRows)
        self.show()
    def SearchRows(self):
        sqlStatement="SELECT Password FROM  
        "+self.ui.lineEditTableName.text()+" where EmailAddress  
        like'"+self.ui.lineEditEmailAddress.text()+"'"
    try:
        conn = sqlite3.connect(self.ui.lineEditDBName.text()+
        ".db")
        cur = conn.cursor()
        cur.execute(sqlStatement)
        row = cur.fetchone()
    if row==None:
        self.ui.labelResponse.setText("Sorry, No User found with  
        this email address")
        self.ui.lineEditPassword.setText("")
```

```py
    else:
        self.ui.labelResponse.setText("Email Address Found,  
        Password of this User is :")
        self.ui.lineEditPassword.setText(row[0])
    except Error as e:
        self.ui.labelResponse.setText("Error in accessing row")
    finally:
        conn.close()
if __name__=="__main__":
    app = QApplication(sys.argv)
    w = MyForm()
    w.show()
    sys.exit(app.exec_())
```

# 工作原理...

您可以在脚本中看到，具有 objectName 属性`pushButtonSearch`的 PushButton 的 click()事件连接到`SearchRows()`方法。这意味着每当单击 PushButton 时，都会调用`SearchRows()`方法。在`SearchRows()`方法中，对`sqlite3`类调用`connect()`方法，并将用户在 LineEdit 小部件中输入的数据库名称传递给`connect()`方法。建立与数据库的连接。定义一个 SQL `search`语句，从所提供的表中获取`Password`列，该表中的电子邮件地址与提供的电子邮件地址匹配。在给定的数据库表上执行`search` SQL 语句。在光标上执行`fetchone()`方法，从执行的 SQL 语句中获取一行。如果获取的行不是`None`，即数据库表中有一行与给定的电子邮件地址匹配，则访问该行中的密码，并将其分配给 object 名称为`lineEditPassword`的 LineEdit 小部件以进行显示。最后，关闭与数据库的连接。

如果在执行 SQL 语句时发生错误，即找不到数据库、表名输入错误，或者给定表中不存在电子邮件地址列，则会通过具有 objectName 属性`labelResponse`的 Label 小部件显示错误消息“访问行时出错”。

运行应用程序后，我们会得到一个对话框，提示我们输入数据库名称、表名和表中的列名。假设我们想要找出在`ECommerce`数据库的`Users`表中，邮箱地址为`bmharwani@yahoo.com`的用户的密码。在框中输入所需信息后，当点击搜索按钮时，用户的密码将从表中获取，并通过行编辑小部件显示，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/ffecd662-0444-472c-adc9-b0709ffc4ed4.png)

如果在 Users 表中找不到提供的电子邮件地址，您将收到消息“抱歉，找不到使用此电子邮件地址的用户”，该消息将通过 Label 小部件显示，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/fa36f35c-539b-4640-b78b-5e75d9cd1447.png)

# 创建一个登录表单 - 应用认证程序

在本教程中，我们将学习如何访问特定表中的行，并将其与提供的信息进行比较。

我们假设数据库`ECommerce`已经存在，并且`ECommerce`数据库中也存在名为`Users`的表。`Users`表包括两列，`EmailAddress`和`Password`。此外，我们假设`Users`表中包含一些行。用户将被提示在登录表单中输入其电子邮件地址和密码。将在`Users`表中搜索指定的电子邮件地址。如果在`Users`表中找到电子邮件地址，则将比较该行中的密码与输入的密码。如果两个密码匹配，则显示欢迎消息；否则，显示指示电子邮件地址或密码不匹配的错误消息。

# 如何做…

以下是了解如何将数据库表中的数据与用户输入的数据进行比较并对用户进行身份验证的步骤：

1.  让我们基于没有按钮的对话框模板创建一个应用程序。

1.  在表单中通过拖放三个 Label 小部件、两个 Line Edit 小部件和一个 Push Button 小部件，添加三个`QLabel`小部件、两个`QLineEdit`小部件和一个`QPushButton`小部件。

1.  将前两个 Label 小部件的文本属性设置为`电子邮件地址`和`密码`。

1.  通过代码删除第三个 Label 小部件的文本属性。

1.  将按钮的文本属性设置为`登录`。

1.  将两个 Line Edit 小部件的 objectName 属性设置为`lineEditEmailAddress`和`lineEditPassword`。

1.  将 Push Button 小部件的 objectName 属性设置为`pushButtonSearch`。

1.  将第三个 Label 小部件的 objectName 属性设置为`labelResponse`。

1.  将应用程序保存为`demoSignInForm.ui`。表单现在将显示如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/8ed32324-b44a-44ce-93b7-6696182ccd07.png)

使用 Qt Designer 创建的用户界面存储在`.ui`文件中，这是一个 XML 文件，需要转换为 Python 代码。通过应用`pyuic5`命令，可以将 XML 文件转换为 Python 代码。生成的 Python 脚本`demoSignInForm.py`可以在本书的源代码包中找到。

1.  将`demoSignInForm.py`文件视为头文件，并将其导入到将调用其用户界面设计的文件中。

1.  创建另一个名为`callSignInForm.pyw`的 Python 文件，并将`demoSignInForm.py`代码导入其中：

```py
import sqlite3, sys
from PyQt5.QtWidgets import QDialog, QApplication
from sqlite3 import Error
from demoSignInForm import *
class MyForm(QDialog):
    def __init__(self):
        super().__init__()
        self.ui = Ui_Dialog()
        self.ui.setupUi(self)
        self.ui.pushButtonSearch.clicked.connect(self.
        SearchRows)
        self.show()
    def SearchRows(self):
        sqlStatement="SELECT EmailAddress, Password FROM Users   
        where EmailAddress like'"+self.ui.lineEditEmailAddress.
        text()+"'and Password like '"+ self.ui.lineEditPassword.
        text()+"'"
        try:
            conn = sqlite3.connect("ECommerce.db")
            cur = conn.cursor()
            cur.execute(sqlStatement)
            row = cur.fetchone()
        if row==None:
            self.ui.labelResponse.setText("Sorry, Incorrect  
            email address or password ")
        else:
            self.ui.labelResponse.setText("You are welcome ")
        except Error as e:
            self.ui.labelResponse.setText("Error in accessing 
            row")
        finally:
            conn.close()
if __name__=="__main__":
    app = QApplication(sys.argv)
    w = MyForm()
    w.show()
    sys.exit(app.exec_())
```

# 工作原理…

您可以在脚本中看到，具有 objectName 属性`pushButtonSearch`的按钮的单击事件与`SearchRows()`方法相连。这意味着每当单击按钮时，都会调用`SearchRows()`方法。在`SearchRows()`方法中，调用`sqlite3`类的`connect()`方法与`ECommerce`数据库建立连接。定义了一个 SQL `search`语句，该语句从`Users`表中获取`EmailAddress`和`Password`列，这些列的电子邮件地址与提供的电子邮件地址匹配。在`Users`表上执行`search` SQL 语句。在光标上执行`fetchone()`方法，以从执行的 SQL 语句中获取一行。如果获取的行不是`None`，即数据库表中存在与给定电子邮件地址和密码匹配的行，则会通过具有 objectName 属性`labelResponse`的 Label 小部件显示欢迎消息。最后，关闭与数据库的连接。

如果在执行 SQL 语句时发生错误，如果找不到数据库，或者表名输入错误，或者`Users`表中不存在电子邮件地址或密码列，则通过具有 objectName 属性`labelResponse`的 Label 小部件显示错误消息“访问行时出错”。

运行应用程序时，您将被提示输入电子邮件地址和密码。输入正确的电子邮件地址和密码后，当您单击“登录”按钮时，您将收到消息“欢迎”，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/0b0a8b36-ce5e-46f4-9667-fdd73d9cded9.png)

但是，如果电子邮件地址或密码输入不正确，您将收到消息“抱歉，电子邮件地址或密码不正确”，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/827e320d-80a2-4214-bc21-a1020968ee47.png)

# 更新数据库表-更改用户密码

在这个示例中，您将学习如何更新数据库中的任何信息。在几乎所有应用程序中，更改密码都是一个非常常见的需求。在这个示例中，我们假设一个名为`ECommerce`的数据库已经存在，并且`ECommerce`数据库中也存在一个名为`Users`的表。`Users`表包含两列，`EmailAddress`和`Password`。此外，我们假设`Users`表中已经包含了一些行。用户将被提示在表单中输入他们的电子邮件地址和密码。将搜索`Users`表以查找指定的电子邮件地址和密码。如果找到具有指定电子邮件地址和密码的行，则将提示用户输入新密码。新密码将被要求输入两次，也就是说，用户将被要求在新密码框和重新输入新密码框中输入他们的新密码。如果两个框中输入的密码匹配，密码将被更改，也就是说，旧密码将被新密码替换。

# 如何做...

从数据库表中删除数据的过程非常关键，执行此类应用程序的任何错误都可能导致灾难。以下是从给定数据库表中删除任何行的步骤：

1.  让我们基于没有按钮的对话框模板创建一个应用程序。

1.  通过拖放五个标签小部件、四个行编辑小部件和一个按钮小部件将它们添加到表单上。

1.  将前四个标签小部件的文本属性设置为`电子邮件地址`、`旧密码`、`新密码`和`重新输入新密码`。

1.  删除第五个标签小部件的文本属性，这是通过代码建立的。将按钮的文本属性设置为`更改密码`。

1.  将四个行编辑小部件的 objectName 属性设置为`lineEditEmailAddress`、`lineEditOldPassword`、`lineEditNewPassword`和`lineEditRePassword`。由于我们不希望密码显示在与密码相关联的任何行编辑小部件中，我们希望用户输入密码时显示星号。

1.  依次从属性编辑器窗口中选择三个行编辑小部件。

1.  选择 echoMode 属性，并将其设置为`Password`，而不是默认的 Normal。

1.  将按钮小部件的 objectName 属性设置为`pushButtonChangePassword`。

1.  将第五个标签小部件的 objectName 属性设置为`labelResponse`。

1.  将应用程序保存为`demoChangePassword.ui`。表单现在将显示如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/7ac023e9-4e95-4f52-b1ec-a2d92853d777.png)

使用 Qt Designer 创建的用户界面存储在`.ui`文件中，这是一个 XML 文件，需要转换为 Python 代码。`pyuic5`命令用于将 XML 文件转换为 Python 代码。本书的源代码包中可以看到生成的 Python 脚本`demoChangePassword.py`。 

1.  将`demoChangePassword.py`脚本视为头文件，并将其导入到您将调用其用户界面设计的文件中。

1.  创建另一个名为`callChangePassword.pyw`的 Python 文件，并将`demoChangePassword.py`代码导入其中：

```py
import sqlite3, sys
from PyQt5.QtWidgets import QDialog, QApplication
from sqlite3 import Error
from demoChangePassword import *
class MyForm(QDialog):
    def __init__(self):
        super().__init__()
        self.ui = Ui_Dialog()
        self.ui.setupUi(self)
        self.ui.pushButtonChangePassword.clicked.connect(self.
        ChangePassword)
        self.show()
    def ChangePassword(self):
        selectStatement="SELECT EmailAddress, Password FROM   
        Users where EmailAddress like '"+self.ui.
        lineEditEmailAddress.text()+"'and Password like '"+         
        self.ui.lineEditOldPassword.text()+"'"
        try:
            conn = sqlite3.connect("ECommerce.db")
            cur = conn.cursor()
            cur.execute(selectStatement)
            row = cur.fetchone()
        if row==None:
            self.ui.labelResponse.setText("Sorry, Incorrect  
            email address or password")
        else:
        if self.ui.lineEditNewPassword.text()==  
          self.ui.lineEditRePassword.text():
            updateStatement="UPDATE Users set Password = '" +             
            self.ui.lineEditNewPassword.text()+"' WHERE   
            EmailAddress like'"+self.ui.lineEditEmailAddress.
            text()+"'"
        with conn:
            cur.execute(updateStatement)
            self.ui.labelResponse.setText("Password successfully 
            changed")
        else:
            self.ui.labelResponse.setText("The two passwords 
            don't match")
        except Error as e:
            self.ui.labelResponse.setText("Error in accessing 
            row")
        finally:
            conn.close()
if __name__=="__main__":
    app = QApplication(sys.argv)
    w = MyForm()
    w.show()
    sys.exit(app.exec_())
```

# 它是如何工作的...

您可以在脚本中看到，具有 objectName 属性`pushButtonChangePassword`的按钮的 click()事件与`ChangePassword()`方法相连。这意味着每当单击按钮时，都会调用`ChangePassword()`方法。在`ChangePassword()`方法中，调用`sqlite3`类的`connect()`方法与`ECommerce`数据库建立连接。定义了一个 SQL `SELECT`语句，该语句从`Users`表中获取与在 LineEdit 小部件中输入的电子邮件地址和密码匹配的`EmailAddress`和`Password`列。在`Users`表上执行 SQL `SELECT`语句。在光标上执行`fetchone()`方法，以从执行的 SQL 语句中获取一行。如果获取的行不是`None`，即数据库表中有一行，则确认两个 LineEdit 小部件`lineEditNewPassword`和`lineEditRePassword`中输入的新密码是否完全相同。如果两个密码相同，则执行`UPDATE` SQL 语句来更新`Users`表，将密码更改为新密码。

如果两个密码不匹配，则不会对数据库表进行更新，并且通过 Label 小部件显示消息“两个密码不匹配”。

如果在执行 SQL `SELECT`或`UPDATE`语句时发生错误，则会通过具有 objectName 属性`labelResponse`的 Label 小部件显示错误消息“访问行时出错”。

运行应用程序时，您将被提示输入电子邮件地址和密码，以及新密码。如果电子邮件地址或密码不匹配，则会通过 Label 小部件显示错误消息“抱歉，电子邮件地址或密码不正确”，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/77868907-dab6-407a-ba11-6a3de7557bf2.png)

如果输入的电子邮件地址和密码正确，但在新密码和重新输入新密码框中输入的新密码不匹配，则屏幕上会显示消息“两个密码不匹配”，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/d50c910f-cd03-4074-8b50-2e3c424b120c.png)

如果电子邮件地址和密码都输入正确，也就是说，如果在数据库表中找到用户行，并且在新密码和重新输入新密码框中输入的新密码匹配，则更新`Users`表，并且在成功更新表后，屏幕上会显示消息“密码已成功更改”，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/03512e11-26e0-47bc-a2b2-4ab3b27a238d.png)

# 从数据库表中删除一行

在本教程中，我们将学习如何从数据库表中删除一行。我们假设名为`ECommerce`的数据库已经存在，并且`ECommerce`数据库中也存在名为`Users`的表。`Users`表包含两列，`EmailAddress`和`Password`。此外，我们假设`User`表中包含一些行。用户将被提示在表单中输入他们的电子邮件地址和密码。将在`Users`表中搜索指定的电子邮件地址和密码。如果在`Users`表中找到具有指定电子邮件地址和密码的任何行，则将提示您确认是否确定要删除该行。如果单击“是”按钮，则将删除该行。

# 如何做…

从数据库表中删除数据的过程非常关键，执行此类应用程序时的任何错误都可能导致灾难。以下是从给定数据库表中删除任何行的步骤：

1.  让我们基于没有按钮的对话框模板创建一个应用程序。

1.  通过将四个 Label 小部件、两个 LineEdit 小部件和三个 PushButton 小部件拖放到表单上，向表单添加四个`QLabel`小部件、两个`QLineEdit`小部件和三个`QPushButton`小部件。

1.  将前三个 Label 小部件的文本属性设置为`电子邮件地址`，`密码`和`你确定吗？`

1.  删除第四个 Label 小部件的文本属性，这是通过代码建立的。

1.  将三个按钮的文本属性设置为`删除用户`，`是`和`否`。

1.  将两个 Line Edit 小部件的 objectName 属性设置为`lineEditEmailAddress`和`lineEditPassword`。

1.  将三个 Push Button 小部件的 objectName 属性设置为`pushButtonDelete`，`pushButtonYes`和`pushButtonNo`。

1.  将第四个 Label 小部件的 objectName 属性设置为`labelResponse`。

1.  将应用程序保存为`demoDeleteUser.ui`。表单现在将显示如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/da1a933e-c763-40db-8e88-c2e13c944c60.png)

使用 Qt Designer 创建的用户界面存储在一个`.ui`文件中，这是一个 XML 文件，需要转换为 Python 代码。使用`pyuic5`命令将 XML 文件转换为 Python 代码。生成的 Python 脚本`demoDeleteUser.py`可以在本书的源代码包中找到。

1.  将`demoDeleteUser.py`脚本视为头文件，并将其导入到将调用其用户界面设计的文件中。

1.  创建另一个名为`callDeleteUser.pyw`的 Python 文件，并将`demoDeleteUser.py`代码导入其中：

```py
import sqlite3, sys
from PyQt5.QtWidgets import QDialog, QApplication
from sqlite3 import Error
from demoDeleteUser import *
class MyForm(QDialog):
    def __init__(self):
        super().__init__()
        self.ui = Ui_Dialog()
        self.ui.setupUi(self)
        self.ui.pushButtonDelete.clicked.connect(self.
        DeleteUser)
        self.ui.pushButtonYes.clicked.connect(self.
        ConfirmDelete)
        self.ui.labelSure.hide()
        self.ui.pushButtonYes.hide()
        self.ui.pushButtonNo.hide()
        self.show()
    def DeleteUser(self):
        selectStatement="SELECT * FROM Users where EmailAddress  
        like'"+self.ui.lineEditEmailAddress.text()+"' 
        and Password like '"+ self.ui.lineEditPassword.
        text()+"'"
        try:
            conn = sqlite3.connect("ECommerce.db")
            cur = conn.cursor()
            cur.execute(selectStatement)
            row = cur.fetchone()
        if row==None:
            self.ui.labelSure.hide()
            self.ui.pushButtonYes.hide()
            self.ui.pushButtonNo.hide()
            self.ui.labelResponse.setText("Sorry, Incorrect 
            email address or password ")
        else:
            self.ui.labelSure.show()
            self.ui.pushButtonYes.show()
            self.ui.pushButtonNo.show()
            self.ui.labelResponse.setText("")
        except Error as e:
            self.ui.labelResponse.setText("Error in accessing 
            user account")
        finally:
            conn.close()
    def ConfirmDelete(self):
        deleteStatement="DELETE FROM Users where EmailAddress    
        like '"+self.ui.lineEditEmailAddress.text()+"' 
        and Password like '"+ self.ui.lineEditPassword.
        text()+"'"
        try:
            conn = sqlite3.connect("ECommerce.db")
            cur = conn.cursor()
        with conn:
            cur.execute(deleteStatement)
            self.ui.labelResponse.setText("User successfully 
            deleted")
        except Error as e:
            self.ui.labelResponse.setText("Error in deleting 
            user account")
        finally:
            conn.close()
if __name__=="__main__":
    app = QApplication(sys.argv)
    w = MyForm()
    w.show()
    sys.exit(app.exec_())
```

# 工作原理…

在这个应用程序中，带有文本“你确定吗？”的 Label 小部件和两个按钮 Yes 和 No 最初是隐藏的。只有当用户输入的电子邮件地址和密码在数据库表中找到时，这三个小部件才会显示出来。这三个小部件使用户能够确认他们是否真的想要删除该行。因此，对这三个小部件调用`hide()`方法，使它们最初不可见。此外，将具有 objectName 属性`pushButtonDelete`的按钮的 click()事件连接到`DeleteUser()`方法。这意味着每当单击删除按钮时，都会调用`DeleteUser()`方法。类似地，具有 objectName 属性`pushButtonYes`的按钮的 click()事件连接到`ConfirmDelete()`方法。这意味着当用户通过单击 Yes 按钮确认删除该行时，将调用`ConfirmDelete()`方法。

在`DeleteUser()`方法中，首先搜索是否存在与输入的电子邮件地址和密码匹配的`Users`表中的任何行。在`sqlite3`类上调用`connect()`方法，与`ECommerce`数据库建立连接。定义了一个 SQL `SELECT`语句，从`Users`表中获取`EmailAddress`和`Password`列，其电子邮件地址和密码与提供的电子邮件地址和密码匹配。在`Users`表上执行 SQL `SELECT`语句。在游标上执行`fetchone()`方法，从执行的 SQL 语句中获取一行。如果获取的行不是`None`，即数据库表中存在与给定电子邮件地址和密码匹配的行，则会使三个小部件，Label 和两个按钮可见。用户将看到消息“你确定吗？”，然后是两个带有文本 Yes 和 No 的按钮。

如果用户单击 Yes 按钮，则会执行`ConfirmDelete()`方法。在`ConfirmDelete()`方法中，定义了一个 SQL `DELETE`方法，用于从`Users`表中删除与输入的电子邮件地址和密码匹配的行。在与`ECommerce`数据库建立连接后，执行 SQL `DELETE`方法。如果成功从`Users`表中删除了行，则通过 Label 小部件显示消息“用户成功删除”；否则，将显示错误消息“删除用户帐户时出错”。

在运行应用程序之前，我们将启动一个名为 SQLite 数据库浏览器的可视化工具。该可视化工具使我们能够创建，编辑和查看数据库表及其中的行。使用 SQLite 数据库浏览器，我们将首先查看“用户”表中的现有行。之后，应用程序将运行并删除一行。再次从 SQLite 数据库浏览器中，我们将确认该行是否真的已从“用户”表中删除。

因此，启动 SQLite 数据库浏览器并在主菜单下方点击“打开数据库”选项卡。浏览并从当前文件夹中选择“电子商务”数据库。 “电子商务”数据库显示由两列“电子邮件地址”和“密码”组成的“用户”表。单击“执行 SQL”按钮以编写 SQL 语句。在窗口中，写入 SQL 语句`select * from Users`，然后单击运行图标。 “用户”表中的所有现有行将显示在屏幕上。您可以在以下屏幕截图中看到“用户”表有两行：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/f8bf5ccc-af6f-405e-a4e6-775a76665be4.png)

运行应用程序后，您将被提示输入您的电子邮件地址和密码。如果您输入错误的电子邮件地址和密码，您将收到消息“抱歉，电子邮件地址或密码不正确”，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/4e593290-b796-4841-8621-20bb4bba5aa5.png)

在输入正确的电子邮件地址和密码后，当您点击删除用户按钮时，三个小部件——标签小部件和两个按钮，将变为可见，并且您会收到消息“您确定吗？”，以及两个按钮“Yes”和“No”，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/889013f0-8d85-4888-a358-90ea905de172.png)

点击“Yes”按钮后，“用户”表中与提供的电子邮件地址和密码匹配的行将被删除，并且通过标签小部件显示确认消息“用户成功删除”，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/69261dfc-02f4-4a0d-a063-7d4c1fd4ba6c.png)

让我们通过可视化工具检查行是否实际上已从用户表中删除。因此，启动 SQLite 数据库浏览器并在主菜单下方点击“打开数据库”选项卡。浏览并从当前文件夹中选择“电子商务”数据库。 “电子商务”数据库将显示“用户”表。单击“执行 SQL”按钮以编写 SQL 语句。在窗口中，写入 SQL 语句`select * from Users`，然后单击运行图标。 “用户”表中的所有现有行将显示在屏幕上。

在运行应用程序之前，我们看到“用户”表中有两行。这次，您只能在“用户”表中看到一行（请参阅下面的屏幕截图），证实已从“用户”表中删除了一行：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/332e5a96-cbdf-4514-93c9-6a1aa708de21.png)


# 第二十章：使用图形

在每个应用程序中，图形在使其更加用户友好方面起着重要作用。图形使概念更容易理解。在本章中，我们将涵盖以下主题：

+   显示鼠标坐标

+   显示鼠标点击和释放的坐标

+   显示鼠标按钮点击的点

+   在两次鼠标点击之间绘制一条线

+   绘制不同类型的线

+   绘制所需大小的圆

+   在两次鼠标点击之间绘制一个矩形

+   以所需的字体和大小绘制文本

+   创建显示不同图形工具的工具栏

+   使用 Matplotlib 绘制一条线

+   使用 Matplotlib 绘制条形图

# 介绍

为了在 Python 中进行绘制和绘画，我们将使用几个类。其中最重要的是`QPainter`类。

这个类用于绘图。它可以绘制线条、矩形、圆形和复杂的形状。在使用`QPainter`绘图时，可以使用`QPainter`类的笔来定义绘图的颜色、笔/刷的粗细、样式，以及线条是实线、虚线还是点划线等。

本章中使用了`QPainter`类的几种方法来绘制不同的形状。以下是其中的一些：

+   `QPainter::drawLine()`: 该方法用于在两组*x*和*y*坐标之间绘制一条线

+   `QPainter::drawPoints()`: 该方法用于在通过提供的*x*和*y*坐标指定的位置绘制一个点

+   `QPainter::drawRect()`: 该方法用于在两组*x*和*y*坐标之间绘制一个矩形

+   `QPainter::drawArc()`: 该方法用于从指定的中心位置绘制弧，介于两个指定的角度之间，并具有指定的半径

+   `QPainter::drawText()`: 该方法用于以指定的字体样式、颜色和大小绘制文本

为了实际显示图形所需的不同类和方法，让我们遵循一些操作步骤。

# 显示鼠标坐标

要用鼠标绘制任何形状，您需要知道鼠标按钮的点击位置，鼠标拖动到何处以及鼠标按钮释放的位置。只有在知道鼠标按钮点击的坐标后，才能执行命令来绘制不同的形状。在这个教程中，我们将学习在表单上显示鼠标移动到的*x*和*y*坐标。

# 操作步骤...

在这个教程中，我们将跟踪鼠标移动，并在表单上显示鼠标移动的*x*和*y*坐标。因此，在这个应用程序中，我们将使用两个 Label 小部件，一个用于显示消息，另一个用于显示鼠标坐标。创建此应用程序的完整步骤如下：

1.  让我们创建一个基于没有按钮的对话框模板的应用程序。

1.  通过将两个 Label 小部件拖放到表单上，向表单添加两个`QLabel`小部件。

1.  将第一个 Label 小部件的文本属性设置为`This app will display x,y coordinates where mouse is moved on`。

1.  删除第二个 Label 小部件的文本属性，因为它的文本属性将通过代码设置。

1.  将应用程序保存为`demoMousetrack.ui`。

表单现在将显示如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/42107aa5-261d-42aa-8327-ed81cf97bbae.png)

使用 Qt Designer 创建的用户界面存储在`.ui`文件中，这是一个 XML 文件，需要转换为 Python 代码。使用`pyuic5`实用程序将 XML 文件转换为 Python 代码。书籍的源代码包中可以看到生成的 Python 脚本`demoMousetrack.py`。

1.  将`demoMousetrack.py`脚本视为头文件，并将其从中调用用户界面设计的文件中导入。

1.  创建另一个名为`callMouseTrack.pyw`的 Python 文件，并将`demoMousetrack.py`代码导入其中：

```py
import sys
from PyQt5.QtWidgets import QDialog, QApplication
from demoMousetrack import *
class MyForm(QDialog):
    def __init__(self):
        super().__init__()
        self.ui = Ui_Dialog()
        self.setMouseTracking(True)
        self.ui.setupUi(self)
        self.show()
    def mouseMoveEvent(self, event):
        x = event.x()
        y = event.y()
        text = "x: {0}, y: {1}".format(x, y)
        self.ui.label.setText(text)
if __name__=="__main__":
    app = QApplication(sys.argv)
    w = MyForm()
    w.show()
    sys.exit(app.exec_())
```

# 工作原理...

为了使应用程序跟踪鼠标，使用了一个方法`setMouseTracking(True)`。这个方法将感应鼠标移动，每当鼠标移动时，它将调用`mouseMoveEvent()`方法。在`mouseMoveEvent()`中，对`event`对象调用`x`和`y`方法以获取鼠标位置的*x*和*y*坐标值。*x*和*y*坐标分别赋给`x`和`y`变量。通过标签小部件以所需的格式显示*x*和*y*坐标的值。

运行应用程序时，将会收到一条消息，提示鼠标移动时将显示其*x*和*y*坐标值。当您在表单上移动鼠标时，鼠标位置的*x*和*y*坐标将通过第二个标签小部件显示，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/da24bcb9-6682-437e-96ac-72ca5f5d78f5.png)

# 显示鼠标按下和释放的坐标

在这个示例中，我们将学习显示鼠标按下的*x*和*y*坐标，以及鼠标释放的坐标。

# 如何做...

两种方法，`mousePressEvent()`和`mouseReleaseEvent()`，在这个示例中将起到重要作用。当鼠标按下时，`mousePressEvent()`方法将自动被调用，并在鼠标按下事件发生时显示*x*和*y*坐标。同样，`mouseReleaseEvent()`方法将在鼠标按钮释放时自动被调用。两个标签小部件将用于显示鼠标按下和释放的坐标。以下是创建这样一个应用程序的步骤：

1.  让我们基于没有按钮的对话框模板创建一个应用程序。

1.  通过将三个标签小部件拖放到表单上，向表单添加三个`QLabel`小部件。

1.  将第一个标签小部件的文本属性设置为`显示鼠标按下和释放的*x*和*y*坐标`。

1.  删除第二个和第三个标签小部件的文本属性，因为它们的文本属性将通过代码设置。

1.  将第二个标签小部件的 objectName 属性设置为`labelPress`，因为它将用于显示鼠标按下的位置的*x*和*y*坐标。

1.  将第三个标签小部件的 objectName 属性设置为`labelRelease`，因为它将用于显示鼠标释放的位置的*x*和*y*坐标。

1.  将应用程序保存为`demoMouseClicks.ui`。

表单现在将显示如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/349370c8-045c-4665-a596-a08ee0f4ca45.png)

使用 Qt Designer 创建的用户界面存储在一个`.ui`文件中，这是一个 XML 文件，需要转换为 Python 代码。使用`pyuic5`实用程序将 XML 文件转换为 Python 代码。生成的 Python 脚本`demoMouseClicks.py`可以在本书的源代码包中看到。

1.  将`demoMouseClicks.py`脚本视为头文件，并将其导入到您将调用其用户界面设计的文件中。

1.  创建另一个名为`callMouseClickCoordinates.pyw`的 Python 文件，并将`demoMouseClicks.py`代码导入其中：

```py
import sys
from PyQt5.QtWidgets import QDialog, QApplication
from demoMouseClicks import *
class MyForm(QDialog):
    def __init__(self):
        super().__init__()
        self.ui = Ui_Dialog()
        self.ui.setupUi(self)
        self.show()
    def mousePressEvent(self, event):
        if event.buttons() & QtCore.Qt.LeftButton:
            x = event.x()
            y = event.y()
            text = "x: {0}, y: {1}".format(x, y)
            self.ui.labelPress.setText('Mouse button pressed at 
            '+text)
    def mouseReleaseEvent(self, event):
        x = event.x()
        y = event.y()
        text = "x: {0}, y: {1}".format(x, y)
        self.ui.labelRelease.setText('Mouse button released at 
        '+text)
        self.update()
if __name__=="__main__":
    app = QApplication(sys.argv)
    w = MyForm()
    w.show()
    sys.exit(app.exec_())
```

# 它是如何工作的...

当单击鼠标时，会自动调用两个方法。当按下鼠标按钮时，会调用`mousePressEvent()`方法，当释放鼠标按钮时，会调用`mouseReleaseEvent()`方法。为了显示鼠标点击和释放的位置的*x*和*y*坐标，我们使用这两种方法。在这两种方法中，我们只需在`event`对象上调用`x()`和`y()`方法来获取鼠标位置的*x*和*y*坐标值。获取的*x*和*y*值将分别赋给`x`和`y`变量。`x`和`y`变量中的值将以所需的格式进行格式化，并通过两个 Label 部件显示出来。

运行应用程序时，将会收到一个消息，显示鼠标按下和释放的位置的*x*和*y*坐标。

当你按下鼠标按钮并释放它时，鼠标按下和释放的位置的*x*和*y*坐标将通过两个 Label 部件显示出来，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/d2b7047e-aabd-43b8-9b9a-dff3be87f80e.png)

# 显示鼠标点击的点

在这个教程中，我们将学习在窗体上显示鼠标点击的点。这里的点指的是一个小圆点。也就是说，无论用户在哪里按下鼠标，都会在那个坐标处出现一个小圆点。你还将学会定义小圆点的大小。

# 如何做...

在这个教程中，将使用`mousePressEvent()`方法，因为它是在窗体上按下鼠标时自动调用的方法。在`mousePressEvent()`方法中，我们将执行命令来显示所需大小的点或圆点。以下是了解如何在单击鼠标的地方在窗体上显示一个点或圆点的步骤：

1.  让我们基于没有按钮的对话框模板创建一个应用程序。

1.  通过拖放 Label 部件将`QLabel`部件添加到窗体中。

1.  将 Label 部件的文本属性设置为“单击鼠标以显示一个点的位置”。

1.  将应用程序保存为`demoDrawDot.ui`。

窗体现在将显示如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/ec7eda2f-85a9-454a-80a7-41c9fc88a2ea.png)

使用 Qt Designer 创建的用户界面存储在一个`.ui`文件中，这是一个 XML 文件，需要转换为 Python 代码。使用`pyuic5`工具将 XML 文件转换为 Python 代码。生成的 Python 脚本`demoDrawDot.py`可以在本书的源代码包中找到。

1.  将`demoDrawDot.py`脚本视为头文件，并将其从用户界面设计中调用的文件中导入。

1.  创建另一个名为`callDrawDot.pyw`的 Python 文件，并将`demoDrawDot.py`代码导入其中：

```py
import sys
from PyQt5.QtWidgets import QDialog, QApplication
from PyQt5.QtGui import QPainter, QPen
from PyQt5.QtCore import Qt
from demoDrawDot import *
class MyForm(QDialog):
    def __init__(self):
        super().__init__()
        self.ui = Ui_Dialog()
        self.ui.setupUi(self)
        self.pos1 = [0,0]
        self.show()
    def paintEvent(self, event):
        qp = QPainter()
        qp.begin(self)
        pen = QPen(Qt.black, 5)
        qp.setPen(pen)
        qp.drawPoint(self.pos1[0], self.pos1[1])
        qp.end()
    def mousePressEvent(self, event):
        if event.buttons() & QtCore.Qt.LeftButton:
            self.pos1[0], self.pos1[1] = event.pos().x(), 
            event.pos().y()
            self.update()
if __name__=="__main__":
    app = QApplication(sys.argv)
    w = MyForm()
    w.show()
    sys.exit(app.exec_())
```

# 工作原理...

因为我们想要显示鼠标点击的点，所以使用了`mousePressEvent()`方法。在`mousePressEvent()`方法中，对`event`对象调用`pos().x()`和`pos().y()`方法来获取*x*和*y*坐标的位置，并将它们分配给`pos1`数组的`0`和`1`元素。也就是说，`pos1`数组被初始化为鼠标点击的*x*和*y*坐标值。在初始化`pos1`数组之后，调用`self.update()`方法来调用`paintEvent()`方法。

在`paintEvent()`方法中，通过名称为`qp`的`QPainter`类对象定义了一个对象。通过名称为 pen 的`QPen`类对象设置了笔的粗细和颜色。最后，通过在`pos1`数组中定义的位置调用`drawPoint()`方法显示一个点。

运行应用程序时，将会收到一条消息，指出鼠标按钮点击的地方将显示一个点。当您点击鼠标时，一个点将出现在那个位置，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/ba0d76c7-9948-4b42-9843-1fd8aaf1b17c.png)

# 在两次鼠标点击之间画一条线

在这个示例中，我们将学习如何在两个点之间显示一条线，从鼠标按钮点击的地方到鼠标按钮释放的地方。这个示例的重点是理解如何处理鼠标按下和释放事件，如何访问鼠标按钮点击和释放的*x*和*y*坐标，以及如何在鼠标按钮点击的位置和鼠标按钮释放的位置之间绘制一条线。

# 如何操作...

这个示例中的主要方法是`mousePressEvent()`、`mouseReleaseEvent()`和`paintEvent()`。`mousePressEvent()`和`mouseReleaseEvent()`方法在鼠标按钮被点击或释放时自动执行。这两种方法将用于访问鼠标按钮被点击和释放的*x*和*y*坐标。最后，`paintEvent()`方法用于在`mousePressEvent()`和`mouseReleaseEvent()`方法提供的坐标之间绘制一条线。以下是创建此应用程序的逐步过程：

1.  让我们基于没有按钮的对话框模板创建一个应用程序。

1.  通过拖放标签小部件到表单上，向表单添加一个`QLabel`小部件。

1.  将标签小部件的文本属性设置为`单击鼠标并拖动以绘制所需大小的线`。

1.  将应用程序保存为`demoDrawLine.ui`。

表单现在将显示如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/14d862a2-330c-4b2a-a5a9-c82308f27209.png)

使用 Qt Designer 创建的用户界面存储在一个`.ui`文件中，这是一个 XML 文件，需要转换为 Python 代码。`pyuic5`实用程序用于将 XML 文件转换为 Python 代码。生成的 Python 脚本`demoDrawLine.py`可以在书的源代码包中看到。

1.  将`demoDrawLine.py`脚本视为头文件，并将其导入到将调用其用户界面设计的文件中。

1.  创建另一个名为`callDrawLine.pyw`的 Python 文件，并将`demoDrawLine.py`代码导入其中：

```py
import sys
from PyQt5.QtWidgets import QDialog, QApplication
from PyQt5.QtGui import QPainter
from demoDrawLine import *
class MyForm(QDialog):
    def __init__(self):
        super().__init__()
        self.ui = Ui_Dialog()
        self.ui.setupUi(self)
        self.pos1 = [0,0]
        self.pos2 = [0,0]
        self.show()
    def paintEvent(self, event):
        qp = QPainter()
        qp.begin(self)
        qp.drawLine(self.pos1[0], self.pos1[1], self.pos2[0], 
        self.pos2[1])
        qp.end()
    def mousePressEvent(self, event):
        if event.buttons() & QtCore.Qt.LeftButton:
            self.pos1[0], self.pos1[1] = event.pos().x(), 
            event.pos().y()
    def mouseReleaseEvent(self, event):
            self.pos2[0], self.pos2[1] = event.pos().x(), 
            event.pos().y()
            self.update()
if __name__=="__main__":
    app = QApplication(sys.argv)
    w = MyForm()
    w.show()
    sys.exit(app.exec_())
```

# 工作原理...

由于我们想要在鼠标按钮点击和释放的位置之间显示一条线，我们将使用两种方法，`mousePressEvent()`和`mouseReleaseEvent()`。顾名思义，`mousePressEvent()`方法在鼠标按钮按下时自动调用。同样，`mouseReleaseEvent()`方法在鼠标按钮释放时自动调用。在这两种方法中，我们将简单地保存鼠标按钮点击和释放的*x*和*y*坐标的值。在这个应用程序中定义了两个数组`pos1`和`pos2`，其中`pos1`存储鼠标按钮点击的位置的*x*和*y*坐标，`pos2`数组存储鼠标按钮释放的位置的*x*和*y*坐标。一旦鼠标按钮点击和释放的位置的*x*和*y*坐标被分配给`pos1`和`pos2`数组，`self.update()`方法在`mouseReleaseEvent()`方法中被调用以调用`paintEvent()`方法。在`paintEvent()`方法中，调用`drawLine()`方法，并将存储在`pos1`和`pos2`数组中的*x*和*y*坐标传递给它，以在鼠标按下和鼠标释放的位置之间绘制一条线。

运行应用程序时，您将收到一条消息，要求在需要绘制线条的位置之间单击并拖动鼠标按钮。因此，单击鼠标按钮并保持鼠标按钮按下，将其拖动到所需位置，然后释放鼠标按钮。将在鼠标按钮单击和释放的位置之间绘制一条线，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/af765355-e32c-4cbc-8c68-130b778aa710.png)

# 绘制不同类型的线条

在本示例中，我们将学习在两个点之间显示不同类型的线条，从鼠标单击位置到释放鼠标按钮的位置。用户将显示不同的线条类型可供选择，例如实线、虚线、虚线点线等。线条将以所选线条类型绘制。

# 如何做...

用于定义绘制形状的笔的大小或厚度的是`QPen`类。在这个示例中，使用`QPen`类的`setStyle()`方法来定义线条的样式。以下是绘制不同样式线条的逐步过程：

1.  让我们基于没有按钮的对话框模板创建一个应用程序。

1.  通过在表单上拖放一个标签小部件来向表单添加一个`QLabel`小部件。

1.  通过拖放一个列表小部件项目在表单上添加一个`QListWidget`小部件。

1.  将标签小部件的文本属性设置为`从列表中选择样式，然后单击并拖动以绘制一条线`。

1.  将应用程序保存为`demoDrawDiffLine.ui`。

1.  列表小部件将用于显示不同类型的线条，因此右键单击列表小部件并选择“编辑项目”选项以向列表小部件添加几种线条类型。单击打开的对话框框底部的+（加号）按钮，并添加几种线条类型，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/2d9c24db-f1d3-4c5b-86f8-946e1db3c09b.png)

1.  将列表小部件项目的 objectName 属性设置为`listWidgetLineType`。

表单现在将显示如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/3da8852a-3a65-41e2-94d6-9a50803b8a8f.png)

使用 Qt Designer 创建的用户界面存储在`.ui`文件中，这是一个 XML 文件，需要转换为 Python 代码。`pyuic5`实用程序用于将 XML 文件转换为 Python 代码。生成的 Python 脚本`demoDrawDiffLine.py`可以在本书的源代码包中看到。

1.  将`demoDrawDiffLine.py`脚本视为头文件，并将其导入到您将调用其用户界面设计的文件中。

1.  创建另一个名为`callDrawDiffLine.pyw`的 Python 文件，并将`demoDrawDiffLine.py`代码导入其中：

```py
import sys
from PyQt5.QtWidgets import QDialog, QApplication
from PyQt5.QtGui import QPainter, QPen
from PyQt5.QtCore import Qt
from demoDrawDiffLine import *
class MyForm(QDialog):
    def __init__(self):
        super().__init__()
        self.ui = Ui_Dialog()
        self.ui.setupUi(self)
        self.lineType="SolidLine"
        self.pos1 = [0,0]
        self.pos2 = [0,0]
        self.show()
    def paintEvent(self, event):
        qp = QPainter()
        qp.begin(self)
        pen = QPen(Qt.black, 4)
        self.lineTypeFormat="Qt."+self.lineType
        if self.lineTypeFormat == "Qt.SolidLine":
            pen.setStyle(Qt.SolidLine)
            elif self.lineTypeFormat == "Qt.DashLine":
            pen.setStyle(Qt.DashLine)
            elif self.lineTypeFormat =="Qt.DashDotLine":
                pen.setStyle(Qt.DashDotLine)
            elif self.lineTypeFormat =="Qt.DotLine":
                pen.setStyle(Qt.DotLine)
            elif self.lineTypeFormat =="Qt.DashDotDotLine":
                pen.setStyle(Qt.DashDotDotLine)
                qp.setPen(pen)
                qp.drawLine(self.pos1[0], self.pos1[1], 
                self.pos2[0], self.pos2[1])
                qp.end()
    def mousePressEvent(self, event):
        if event.buttons() & QtCore.Qt.LeftButton:
            self.pos1[0], self.pos1[1] = event.pos().x(), 
            event.pos().y()
    def mouseReleaseEvent(self, event):
        self.lineType=self.ui.listWidgetLineType.currentItem()
        .text()
        self.pos2[0], self.pos2[1] = event.pos().x(), 
        event.pos().y()
        self.update()
if __name__=="__main__":
    app = QApplication(sys.argv)
    w = MyForm()
    w.show()
    sys.exit(app.exec_())
```

# 它是如何工作的...

必须在鼠标按下和鼠标释放位置之间绘制一条线，因此我们将在此应用程序中使用两种方法，`mousePressEvent()`和`mouseReleaseEvent()`。当单击鼠标左键时，`mousePressEvent()`方法会自动调用。同样，当鼠标按钮释放时，`mouseReleaseEvent()`方法会自动调用。

在这两种方法中，我们将保存鼠标单击和释放时的*x*和*y*坐标的值。在这个应用程序中定义了两个数组`pos1`和`pos2`，其中`pos1`存储鼠标单击的位置的*x*和*y*坐标，`pos2`数组存储鼠标释放的位置的*x*和*y*坐标。在`mouseReleaseEvent()`方法中，我们从列表小部件中获取用户选择的线类型，并将所选的线类型分配给`lineType`变量。此外，在`mouseReleaseEvent()`方法中调用了`self.update()`方法来调用`paintEvent()`方法。在`paintEvent()`方法中，您定义了一个宽度为`4`像素的画笔，并将其分配为黑色。此外，您为画笔分配了一个与用户从列表小部件中选择的线类型相匹配的样式。最后，调用`drawLine()`方法，并将存储在`pos1`和`pos2`数组中的*x*和*y*坐标传递给它，以在鼠标按下和鼠标释放位置之间绘制一条线。所选的线将以从列表小部件中选择的样式显示。

运行应用程序时，您将收到一条消息，要求从列表中选择线类型，并在需要线的位置之间单击并拖动鼠标按钮。因此，在选择所需的线类型后，单击鼠标按钮并保持鼠标按钮按下，将其拖动到所需位置，然后释放鼠标按钮。将在鼠标按钮单击和释放的位置之间绘制一条线，以所选的样式显示在列表中。以下截图显示了不同类型的线：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/9b53d16b-2706-4bad-b105-9f86f5163ee6.png)

# 绘制所需大小的圆

在这个示例中，我们将学习如何绘制一个圆。用户将点击并拖动鼠标来定义圆的直径，圆将根据用户指定的直径进行绘制。

# 如何做...

一个圆实际上就是从 0 到 360 度绘制的弧。弧的长度，或者可以说是圆的直径，由鼠标按下事件和鼠标释放事件的距离确定。在鼠标按下事件到鼠标释放事件之间内部定义了一个矩形，并且圆在该矩形内绘制。以下是创建此应用程序的完整步骤：

1.  让我们创建一个基于无按钮对话框模板的应用程序。

1.  通过拖放一个标签小部件到表单上，向表单添加一个`QLabel`小部件。

1.  将标签小部件的文本属性设置为`单击鼠标并拖动以绘制所需大小的圆`。

1.  将应用程序保存为`demoDrawCircle.ui`。表单现在将显示如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/53947d76-a10c-4516-9a77-6e50d2412f11.png)

使用 Qt Designer 创建的用户界面存储在`.ui`文件中，它是一个 XML 文件。通过应用`pyuic5`实用程序将 XML 文件转换为 Python 代码。您可以在本书的源代码包中找到生成的 Python 代码`demoDrawCircle.py`。

1.  将`demoDrawCircle.py`脚本视为头文件，并将其导入到您将调用其用户界面设计的文件中。

1.  创建另一个名为`callDrawCircle.pyw`的 Python 文件，并将`demoDrawCircle.py`代码导入其中：

```py
import sys
from PyQt5.QtWidgets import QDialog, QApplication
from PyQt5.QtGui import QPainter
from demoDrawCircle import *
class MyForm(QDialog):
    def __init__(self):
        super().__init__()
        self.ui = Ui_Dialog()
        self.ui.setupUi(self)
        self.pos1 = [0,0]
        self.pos2 = [0,0]
        self.show()
    def paintEvent(self, event):
        width = self.pos2[0]-self.pos1[0]
        height = self.pos2[1] - self.pos1[1]
        qp = QPainter()
        qp.begin(self)
        rect = QtCore.QRect(self.pos1[0], self.pos1[1], width, 
        height)
        startAngle = 0
        arcLength = 360 *16
        qp.drawArc(rect, startAngle, arcLength)
        qp.end()
    def mousePressEvent(self, event):
        if event.buttons() & QtCore.Qt.LeftButton:
            self.pos1[0], self.pos1[1] = event.pos().x(), 
            event.pos().y()
    def mouseReleaseEvent(self, event):
        self.pos2[0], self.pos2[1] = event.pos().x(), 
        event.pos().y()
        self.update()
if __name__=="__main__":
    app = QApplication(sys.argv)
    w = MyForm()
    w.show()
    sys.exit(app.exec_())
```

# 工作原理...

为了在鼠标按下和释放的位置之间绘制直径定义的圆，我们将使用两种方法，`mousePressEvent()`和`mouseReleaseEvent()`。当鼠标按钮按下时，`mousePressEvent()`方法会自动调用，当鼠标按钮释放时，`mouseReleaseEvent()`方法会自动调用。在这两种方法中，我们将简单地保存鼠标按下和释放的*x*和*y*坐标的值。定义了两个数组`pos1`和`pos2`，其中`pos1`数组存储鼠标按下的位置的*x*和*y*坐标，`pos2`数组存储鼠标释放的位置的*x*和*y*坐标。在`mouseReleaseEvent()`方法中调用的`self.update()`方法将调用`paintEvent()`方法。在`paintEvent()`方法中，通过找到鼠标按下和鼠标释放位置的*x*坐标之间的差异来计算矩形的宽度。类似地，通过找到鼠标按下和鼠标释放事件的*y*坐标之间的差异来计算矩形的高度。

圆的大小将等于矩形的宽度和高度，也就是说，圆将在用户用鼠标指定的边界内创建。 

此外，在`paintEvent()`方法中，调用了`drawArc()`方法，并将矩形、弧的起始角度和弧的长度传递给它。起始角度被指定为`0`。

运行应用程序时，会收到一条消息，要求点击并拖动鼠标按钮以定义要绘制的圆的直径。因此，点击鼠标按钮并保持鼠标按钮按下，将其拖动到所需位置，然后释放鼠标按钮。将在鼠标按下和释放的位置之间绘制一个圆，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/361dd5cf-84ec-4f7e-91da-d01e1547202f.png)

# 在两次鼠标点击之间绘制一个矩形

在这个示例中，我们将学习在表单上显示鼠标按下和释放的两个点之间的矩形。

# 如何做...

这是一个非常简单的应用程序，其中使用`mousePressEvent()`和`mouseReleaseEvent()`方法来分别找到鼠标按下和释放的位置的*x*和*y*坐标。然后，调用`drawRect()`方法来从鼠标按下的位置到鼠标释放的位置绘制矩形。创建此应用程序的逐步过程如下：

1.  让我们基于没有按钮的对话框模板创建一个应用程序。

1.  在表单上通过拖放标签小部件添加一个`QLabel`小部件。

1.  将标签小部件的文本属性设置为`点击鼠标并拖动以绘制所需大小的矩形`。

1.  将应用程序保存为`demoDrawRectangle.ui`。表单现在将显示如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/23480372-2821-4af3-abba-cb0ad86dc49b.png)

使用 Qt Designer 创建的用户界面存储在一个`.ui`文件中，这是一个 XML 文件，需要转换为 Python 代码。使用`pyuic5`工具将 XML 文件转换为 Python 代码。生成的 Python 脚本`demoDrawRectangle.py`可以在本书的源代码包中找到。

1.  将`demoDrawRectangle.py`脚本视为头文件，并将其导入到将调用其用户界面设计的文件中。

1.  创建另一个名为`callDrawRectangle.pyw`的 Python 文件，并将`demoDrawRectangle.py`的代码导入其中：

```py
import sys
from PyQt5.QtWidgets import QDialog, QApplication
from PyQt5.QtGui import QPainter
from demoDrawRectangle import *
class MyForm(QDialog):
    def __init__(self):
        super().__init__()
        self.ui = Ui_Dialog()
        self.ui.setupUi(self)
        self.pos1 = [0,0]
        self.pos2 = [0,0]
        self.show()
    def paintEvent(self, event):
        width = self.pos2[0]-self.pos1[0]
        height = self.pos2[1] - self.pos1[1]
        qp = QPainter()
        qp.begin(self)
        qp.drawRect(self.pos1[0], self.pos1[1], width, height)
        qp.end()
    def mousePressEvent(self, event):
        if event.buttons() & QtCore.Qt.LeftButton:
            self.pos1[0], self.pos1[1] = event.pos().x(), 
            event.pos().y()
    def mouseReleaseEvent(self, event):
        self.pos2[0], self.pos2[1] = event.pos().x(), 
        event.pos().y()
        self.update()
if __name__=="__main__":
    app = QApplication(sys.argv)
    w = MyForm()
    w.show()
    sys.exit(app.exec_())
```

# 工作原理...

为了在鼠标按钮按下和释放的位置之间绘制矩形，我们将使用两种方法，`mousePressEvent()`和`mouseReleaseEvent()`。当鼠标按钮按下时，`mousePressEvent()`方法会自动被调用，当鼠标按钮释放时，`mouseReleaseEvent()`方法会自动被调用。在这两种方法中，我们将简单地保存鼠标按钮单击和释放时的*x*和*y*坐标的值。定义了两个数组`pos1`和`pos2`，其中`pos1`数组存储鼠标按钮单击的位置的*x*和*y*坐标，`pos2`数组存储鼠标按钮释放的位置的*x*和*y*坐标。在`mouseReleaseEvent()`方法中调用的`self.update()`方法将调用`paintEvent()`方法。在`paintEvent()`方法中，矩形的宽度通过找到鼠标按下和鼠标释放位置的*x*坐标之间的差异来计算。同样，矩形的高度通过找到鼠标按下和鼠标释放事件的*y*坐标之间的差异来计算。

此外，在`paintEvent()`方法中，调用了`drawRect()`方法，并将存储在`pos1`数组中的*x*和*y*坐标传递给它。此外，矩形的宽度和高度也传递给`drawRect()`方法，以在鼠标按下和鼠标释放位置之间绘制矩形。

运行应用程序时，您将收到一条消息，要求单击并拖动鼠标按钮以在所需位置之间绘制矩形。因此，单击鼠标按钮并保持鼠标按钮按下，将其拖动到所需位置，然后释放鼠标按钮。

在鼠标按钮单击和释放的位置之间将绘制一个矩形，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/46b5d873-feca-40d4-a47d-8cd1a9adf217.png)

# 以所需的字体和大小绘制文本

在这个教程中，我们将学习如何以特定的字体和特定的字体大小绘制文本。在这个教程中将需要四个小部件，如文本编辑，列表小部件，组合框和按钮。文本编辑小部件将用于输入用户想要以所需字体和大小显示的文本。列表小部件框将显示用户可以从中选择的不同字体名称。组合框小部件将显示用户可以选择以定义文本大小的字体大小。按钮小部件将启动操作，也就是说，单击按钮后，文本编辑小部件中输入的文本将以所选字体和大小显示。

# 如何操作...

`QPainter`类是本教程的重点。`QPainter`类的`setFont()`和`drawText()`方法将在本教程中使用。`setFont()`方法将被调用以设置用户选择的字体样式和字体大小，`drawText()`方法将以指定的字体样式和大小绘制用户在文本编辑小部件中编写的文本。以下是逐步学习这些方法如何使用的过程：

1.  让我们创建一个基于无按钮对话框模板的应用程序。

1.  将`QLabel`，`QTextEdit`，`QListWidget`，`QComboBox`和`QPushButton`小部件通过拖放标签小部件，文本编辑小部件，列表小部件框，组合框小部件和按钮小部件添加到表单中。

1.  将标签小部件的文本属性设置为“在最左边的框中输入一些文本，选择字体和大小，然后单击绘制文本按钮”。

1.  列表小部件框将用于显示不同的字体，因此右键单击列表小部件框，选择“编辑项目”选项，向列表小部件框添加一些字体名称。单击打开的对话框底部的+（加号）按钮，并添加一些字体名称，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/4af8bf5d-9571-4dfc-adfc-3ff8071a0010.png)

1.  组合框小部件将用于显示不同的字体大小，因此我们需要向组合框小部件添加一些字体大小。右键单击组合框小部件，然后选择“编辑项目”选项。

1.  单击打开的对话框框底部的+（加号）按钮，并添加一些字体大小，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/4a210911-d3db-4235-b58c-be82fae13bb0.png)

1.  将推送按钮小部件的文本属性设置为“绘制文本”。

1.  将列表小部件框的 objectName 属性设置为`listWidgetFont`。

1.  将组合框小部件的 objectName 属性设置为`comboBoxFontSize`。

1.  将推送按钮小部件的 objectName 属性设置为 pushButtonDrawText。

1.  将应用程序保存为`demoDrawText.ui`。

表单现在将显示如下的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/685adb85-c7f3-40db-b4ae-5ad6090a29ea.png)

使用 Qt Designer 创建的用户界面存储在`.ui`文件中，它是一个 XML 文件。通过应用`pyuic5`实用程序将 XML 文件转换为 Python 代码。您可以在本书的源代码包中找到生成的 Python 代码`demoDrawText.py`。

1.  将`demoDrawText.py`脚本视为头文件，并将其导入到将调用其用户界面设计的文件中。

1.  创建另一个名为`callDrawText.pyw`的 Python 文件，并将`demoDrawText.py`代码导入其中：

```py
import sys
from PyQt5.QtWidgets import QDialog, QApplication
from PyQt5.QtGui import QPainter, QColor, QFont
from PyQt5.QtCore import Qt
from demoDrawText import *
class MyForm(QDialog):
    def __init__(self):
        super().__init__()
        self.ui = Ui_Dialog()
        self.ui.setupUi(self)
        self.ui.pushButtonDrawText.clicked.connect(self.
        dispText)
        self.textToDraw=""
        self.fontName="Courier New"
        self.fontSize=5
        self.show()
    def paintEvent(self, event):
        qp = QPainter()
        qp.begin(self)
        qp.setPen(QColor(168, 34, 3))
        qp.setFont(QFont(self.fontName, self.fontSize))
        qp.drawText(event.rect(), Qt.AlignCenter, 
        self.textToDraw)
        qp.end()
    def dispText(self):
        self.fontName=self.ui.listWidgetFont.currentItem().
        text()
        self.fontSize=int(self.ui.comboBoxFontSize.itemText(
        self.ui.comboBoxFontSize.currentIndex()))
        self.textToDraw=self.ui.textEdit.toPlainText()
        self.update()
if __name__=="__main__":
    app = QApplication(sys.argv)
    w = MyForm()
    w.show()
    sys.exit(app.exec_())
```

# 它是如何工作的…

推送按钮小部件的 click()事件连接到`dispText()`方法，也就是说，每当点击推送按钮时，将调用`dispText()`方法。

在`dispText()`方法中，访问从列表小部件框中选择的字体名称，并将其分配给`fontName`变量。此外，访问从组合框中选择的字体大小，并将其分配给`fontSize`变量。除此之外，获取并分配在文本编辑小部件中编写的文本给`textToDraw`变量。最后，调用`self.update()`方法；它将调用`paintEvent()`方法。

在`paintEvent()`方法中，调用`drawText()`方法，将以`fontName`变量分配的字体样式和`fontSize`变量中指定的字体大小绘制在文本编辑小部件中编写的文本。运行应用程序后，您将在极左边看到一个文本编辑小部件，字体名称显示在列表小部件框中，字体大小通过组合框小部件显示。您需要在文本编辑小部件中输入一些文本，从列表小部件框中选择一个字体样式，从组合框小部件中选择一个字体大小，然后单击“绘制文本”按钮。单击“绘制文本”按钮后，文本编辑小部件中编写的文本将以所选字体和所选字体大小显示，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/b50a34fb-8383-4fec-b359-c0a6d2bea7f1.png)

# 创建一个显示不同图形工具的工具栏

在这个示例中，我们将学习创建一个显示三个工具栏按钮的工具栏。这三个工具栏按钮显示线条、圆圈和矩形的图标。当用户从工具栏中单击线条工具栏按钮时，他/她可以在表单上单击并拖动鼠标以在两个鼠标位置之间绘制一条线。类似地，通过单击圆圈工具栏按钮，用户可以通过单击和拖动鼠标在表单上绘制一个圆圈。

# 如何做…

这个示例的重点是帮助您理解如何通过工具栏向用户提供应用程序中经常使用的命令，使它们易于访问和使用。您将学习创建工具栏按钮，定义它们的快捷键以及它们的图标。为工具栏按钮定义图标，您将学习创建和使用资源文件。逐步清晰地解释了每个工具栏按钮的创建和执行过程：

1.  让我们创建一个新应用程序来了解创建工具栏涉及的步骤。

1.  启动 Qt Designer 并创建一个基于主窗口的应用程序。您将获得一个带有默认菜单栏的新应用程序。

1.  您可以右键单击菜单栏，然后从弹出的快捷菜单中选择“删除菜单栏”选项来删除菜单栏。

1.  要添加工具栏，右键单击“主窗口”模板，然后从上下文菜单中选择“添加工具栏”。将在菜单栏下方添加一个空白工具栏，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/cf2901c2-01df-4d2a-88ff-69dd27d17455.png)

我们想要创建一个具有三个工具栏按钮的工具栏，分别是线条、圆形和矩形。由于这三个工具栏按钮将代表三个图标图像，我们假设已经有了图标文件，即扩展名为`.ico`的线条、圆形和矩形文件。

1.  要将工具添加到工具栏中，在“操作编辑器”框中创建一个操作；工具栏中的每个工具栏按钮都由一个操作表示。操作编辑器框通常位于属性编辑器窗口下方。

1.  如果“操作编辑器”窗口不可见，请从“视图”菜单中选择“操作编辑器”。操作编辑器窗口将显示如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/cf7c369d-b4c5-49f3-b5e1-441e3e6143de.png)

1.  在“操作编辑器”窗口中，选择“新建”按钮，为第一个工具栏按钮创建一个操作。您将获得一个对话框，以输入新操作的详细信息。

1.  在文本框中，指定操作的名称为`Circle`。

1.  在“对象名称”框中，操作对象的名称将自动显示，前缀为文本`action`。

1.  在“工具提示”框中，输入任何描述性文本。

1.  在“快捷方式”框中，按下*Ctrl* + *C*字符，将`Ctrl + C`分配为绘制圆形的快捷键。

1.  图标下拉列表显示两个选项，选择资源…和选择文件。

1.  您可以通过单击“选择文件…”选项或从资源文件中为操作分配图标图像：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/e086d3f2-763a-4856-9cbb-e1dc5cd6ba7e.png)

您可以在资源文件中选择多个图标，然后该资源文件可以在不同的应用程序中使用。

1.  选择“选择资源…”选项。您将获得“选择资源”对话框，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/276ca224-3288-4f68-b55a-b73768c3e92c.png)

由于尚未创建任何资源，对话框为空。您会在顶部看到两个图标。第一个图标代表编辑资源，第二个图标代表重新加载。单击“编辑资源”图标后，您将看到如下对话框：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/990531d8-648a-46ec-aacb-cc2ef781da4b.png)

现在让我们看看如何通过以下步骤创建资源文件：

1.  第一步是创建一个资源文件或加载一个现有的资源文件。底部的前三个图标分别代表新资源文件、编辑资源文件和删除。

1.  单击“新建资源文件”图标。将提示您指定资源文件的名称。

1.  让我们将新资源文件命名为`iconresource`。该文件将以扩展名`.qrc`保存。

1.  下一步是向资源文件添加前缀。前缀/路径窗格下的三个图标分别是添加前缀、添加文件和删除。

1.  单击“添加前缀”选项，然后将提示您输入前缀名称。

1.  将前缀输入为`Graphics`。添加前缀后，我们准备向资源文件添加我们的三个图标，圆形、矩形和线条。请记住，我们有三个扩展名为`.ico`的图标文件。

1.  单击“添加文件”选项以添加图标。单击“添加文件”选项后，将要求您浏览到驱动器/目录并选择图标文件。

1.  逐个选择三个图标文件。添加完三个图标后，编辑资源对话框将显示如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/4a5b9237-59a2-458c-9f2a-49c9e5d6fc7c.png)

1.  单击“确定”按钮后，资源文件将显示三个可供选择的图标。

1.  由于我们想要为圆形操作分配一个图标，因此单击圆形图标，然后单击“确定”按钮：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/136162d0-9399-4687-99fa-6c23c97afe3a.png)

所选的圆形图标将被分配给 actionCircle。

1.  类似地，为矩形和线条工具栏按钮创建另外两个操作，`actionRectangle`和`actionLine`。添加了这三个操作后，操作编辑器窗口将显示如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/03c156e2-1e98-4390-92d0-9b0d0fe8d940.png)

1.  要在工具栏中显示工具栏按钮，从操作编辑器窗口中单击一个操作，并保持按住状态，将其拖动到工具栏中。

1.  将应用程序保存为`demoToolBars.ui`。

将三个操作拖动到工具栏后，工具栏将显示如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/314fa220-5b14-4a10-bafb-314fc5d3ce72.png)

`pyuic5`命令行实用程序将把`.ui`（XML）文件转换为 Python 代码，生成的代码将被命名为`demoToolBars.py`。您可以在本书的源代码包中找到`demoToolBars.py`脚本。我们创建的`iconresource.qrc`文件必须在我们继续之前转换为 Python 格式。以下命令行将资源文件转换为 Python 脚本：

```py
pyrcc5 iconresource.qrc -o iconresource_rc.py
```

1.  创建一个名为`callToolBars.pyw`的 Python 脚本，导入代码`demoToolBar.py`，以调用工具栏并绘制从工具栏中选择的图形。脚本文件将如下所示：

```py
import sys
from PyQt5.QtWidgets import QMainWindow, QApplication
from PyQt5.QtGui import QPainter
from demoToolBars import *

class AppWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.pos1 = [0,0]
        self.pos2 = [0,0]
        self.toDraw=""
        self.ui.actionCircle.triggered.connect(self.drawCircle)
        self.ui.actionRectangle.triggered.connect(self.
        drawRectangle)
        self.ui.actionLine.triggered.connect(self.drawLine)
        self.show()

    def paintEvent(self, event):
        qp = QPainter()
        qp.begin(self)
        if self.toDraw=="rectangle":
            width = self.pos2[0]-self.pos1[0]
            height = self.pos2[1] - self.pos1[1]    
            qp.drawRect(self.pos1[0], self.pos1[1], width, 
            height)
        if self.toDraw=="line":
            qp.drawLine(self.pos1[0], self.pos1[1], 
            self.pos2[0], self.pos2[1])
        if self.toDraw=="circle":
            width = self.pos2[0]-self.pos1[0]
            height = self.pos2[1] - self.pos1[1]          
            rect = QtCore.QRect(self.pos1[0], self.pos1[1], 
            width, height)
            startAngle = 0
            arcLength = 360 *16
            qp.drawArc(rect, startAngle, arcLength)     
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
        self.toDraw="circle"

    def drawRectangle(self):
        self.toDraw="rectangle"

    def drawLine(self):
        self.toDraw="line"

app = QApplication(sys.argv)
w = AppWindow()
w.show()
sys.exit(app.exec_())
```

# 它是如何工作的...

每个工具栏按钮的操作的 triggered()信号都连接到相应的方法。actionCircle 工具栏按钮的 triggered()信号连接到`drawCircle()`方法，因此每当从工具栏中选择圆形工具栏按钮时，将调用`drawCircle()`方法。类似地，`actionRectangle`和`actionLine`的 triggered()信号分别连接到`drawRectangle()`和`drawLine()`方法。在`drawCircle()`方法中，一个变量`toDraw`被赋予一个字符串`circle`。`toDraw`变量将用于确定在`paintEvent()`方法中要绘制的图形。`toDraw`变量可以分配任何三个字符串之一，`line`、`circle`或`rectangle`。在`toDraw`变量的值上应用条件分支，相应地，将调用绘制线条、矩形或圆形的方法。

绘制线条、圆形或矩形的大小由鼠标点击确定；用户需要在窗体上单击鼠标，拖动鼠标并释放它到想要绘制线条、圆形或矩形的位置。换句话说，线条的长度、矩形的宽度和高度以及圆形的直径将由鼠标确定。

使用`pos1`和`pos2`两个数组来存储鼠标单击位置和鼠标释放位置的*x*和*y*坐标。*x*和*y*坐标值通过`mousePressEvent()`和`mouseReleaseEvent()`两种方法分配给`pos1`和`pos2`数组。当鼠标按钮被单击时，`mousePressEvent()`方法会自动调用，当鼠标按钮释放时，`mouseReleaseEvent()`方法会自动调用。

在`mouseReleaseEvent()`方法中，分配鼠标释放的位置的*x*和*y*坐标值后，调用`self.update()`方法来调用`paintEvent()`方法。在`paintEvent()`方法中，基于分配给`toDraw`变量的字符串进行分支。如果`toDraw`变量被分配了字符串`line`（由`drawLine()`方法），则将调用`QPainter`类的`drawLine()`方法来在两个鼠标位置之间绘制线。类似地，如果`toDraw`变量被分配了字符串`circle`（由`drawCircle()`方法），则将调用`QPainter`类的`drawArc()`方法来绘制由鼠标位置提供的直径的圆。如果`toDraw`变量由`drawRectangle()`方法分配了字符串`rectangle`，则将调用`QPainter`类的`drawRect()`方法来绘制由鼠标位置提供的宽度和高度的矩形。

运行应用程序后，您将在工具栏上找到三个工具栏按钮，圆形、矩形和线，如下截图所示（左）。点击圆形工具栏按钮，然后在表单上点击鼠标按钮，并保持鼠标按钮按下，拖动以定义圆的直径，然后释放鼠标按钮。将从鼠标按钮点击的位置到释放鼠标按钮的位置绘制一个圆（右）：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/179df12e-a471-46a1-9a71-2178ca4063ce.png)

要绘制一个矩形，点击矩形工具，点击鼠标按钮在表单上的一个位置，并保持鼠标按钮按下，拖动以定义矩形的高度和宽度。释放鼠标按钮时，将在鼠标按下和鼠标释放的位置之间绘制一个矩形（左）。类似地，点击线工具栏按钮，然后在表单上点击鼠标按钮。保持鼠标按钮按下，将其拖动到要绘制线的位置。释放鼠标按钮时，将在鼠标按下和释放的位置之间绘制一条线（右）：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/243bd53e-551a-4efa-a6ed-349fc4e2e1a6.png)

# 使用 Matplotlib 绘制一条线

在本示例中，我们将学习使用 Matplotlib 绘制通过特定*x*和*y*坐标的线。

Matplotlib 是一个 Python 2D 绘图库，使绘制线条、直方图、条形图等复杂的任务变得非常容易。该库不仅可以绘制图表，还提供了一个 API，可以在应用程序中嵌入图表。

# 准备工作

您可以使用以下语句安装 Matplotlib：

```py
pip install matplotlib
```

假设我们要绘制一条线，使用以下一组*x*和*y*坐标：

```py
x=10, y=20
x=20, y=40
x=30, y=60
```

在*x*轴上，`x`的值从`0`开始向右增加，在*y*轴上，`y`的值在底部为`0`，向上移动时增加。因为最后一对坐标是`30`，`60`，所以图表的最大`x`值为`30`，最大`y`值为`60`。

本示例中将使用`matplotlib.pyplot`的以下方法：

+   `title()`: 该方法用于设置图表的标题

+   `xlabel()`: 该方法用于在*x*轴上显示特定文本

+   `ylabel()`: 该方法用于在*y*轴上显示特定文本

+   `plot()`: 该方法用于在指定的*x*和*y*坐标处绘制图表

# 如何操作...

创建一个名为`demoPlotLine.py`的 Python 脚本，并在其中编写以下代码：

```py
import matplotlib.pyplot as graph
graph.title('Plotting a Line!')
graph.xlabel('x - axis')
graph.ylabel('y - axis')
x = [10,20,30]
y = [20,40,60]
graph.plot(x, y)
graph.show()
```

# 工作原理...

您在脚本中导入`matplotlib.pyplot`并将其命名为 graph。使用`title()`方法，您设置图表的标题。然后，调用`xlabel()`和`ylabel()`方法来定义*x*轴和*y*轴的文本。因为我们想要使用三组*x*和*y*坐标绘制一条线，所以定义了两个名为*x*和*y*的数组。在这两个数组中分别定义了我们想要绘制的三个*x*和*y*坐标值的值。调用`plot()`方法，并将这两个*x*和*y*数组传递给它，以使用这两个数组中定义的三个*x*和*y*坐标值绘制线。调用 show 方法显示绘图。

运行应用程序后，您会发现绘制了一条通过指定的*x*和*y*坐标的线。此外，图表将显示指定的标题，绘制一条线！除此之外，您还可以在*x*轴和*y*轴上看到指定的文本，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/b2c02ed5-8d94-4c5c-a52a-bec1ed0b908e.png)

# 使用 Matplotlib 绘制条形图

在本示例中，我们将学习使用 Matplotlib 绘制条形图，比较过去三年业务增长。您将提供 2016 年、2017 年和 2018 年的利润百分比，应用程序将显示代表过去三年利润百分比的条形图。

# 准备工作

假设组织过去三年的利润百分比如下：

+   2016 年：利润为 70%

+   2017 年：利润为 90%

+   2018 年：利润为 80%

您想显示代表利润百分比的条形，并沿*x*轴显示年份：2016 年、2017 年和 2018 年。沿*y*轴，您希望显示代表利润百分比的条形。 *y*轴上的`y`值将从底部的`0`开始增加，向顶部移动时增加，最大值为顶部的`100`。

本示例将使用`matplotlib.pyplot`的以下方法：

+   `title()`: 用于设置图表的标题

+   `bar()`: 从两个提供的数组绘制条形图；一个数组将代表*x*轴的数据，第二个数组将代表*y*轴的数据

+   `plot()`: 用于在指定的*x*和*y*坐标处绘图

# 如何做...

创建一个名为`demoPlotBars.py`的 Python 脚本，并在其中编写以下代码：

```py
import matplotlib.pyplot as graph
years = ['2016', '2017', '2018']
profit = [70, 90, 80]
graph.bar(years, profit)
graph.title('Growth in Business')
graph.plot(100)
graph.show()
```

# 工作原理...

您在脚本中导入`matplotlib.pyplot`并将其命名为 graph。您定义两个数组，years 和 profit，其中 years 数组将包含 2016 年、2017 年和 2018 年的数据，以表示我们想要比较利润的年份。类似地，profit 数组将包含代表过去三年利润百分比的值。然后，调用`bar()`方法，并将这两个数组 years 和 profit 传递给它，以显示比较过去三年利润的条形图。调用`title()`方法显示标题，业务增长。调用`plot()`方法指示*y*轴上的最大`y`值。最后，调用`show()`方法显示条形图。

运行应用程序后，您会发现绘制了一根条形图，显示了组织在过去三年的利润。 *x*轴显示年份，*y*轴显示利润百分比。此外，图表将显示指定的标题，业务增长，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/9b933396-c535-4c40-bc3f-d099b006d5db.png)


# 第二十一章：实现动画

在本章中，您将学习如何对给定的图形图像应用运动，从而实现动画。动画在解释任何机器、过程或系统的实际工作中起着重要作用。在本章中，我们将涵盖以下主题：

+   显示 2D 图形图片

+   点击按钮使球移动

+   制作一个弹跳的球

+   使球根据指定的曲线进行动画

# 介绍

要在 Python 中查看和管理 2D 图形项，我们需要使用一个名为`QGraphicsScene`的类。为了显示`QGraphicsScene`的内容，我们需要另一个名为`QGraphicsView`的类的帮助。基本上，`QGraphicsView`提供了一个可滚动的视口，用于显示`QGraphicsScene`的内容。`QGraphicsScene`充当多个图形项的容器。它还提供了几种标准形状，如矩形和椭圆，包括文本项。还有一点：`QGraphicsScene`使用 OpenGL 来渲染图形。OpenGL 非常高效，可用于显示图像和执行多媒体处理任务。`QGraphicsScene`类提供了几种方法，可帮助添加或删除场景中的图形项。也就是说，您可以通过调用`addItem`函数向场景添加任何图形项。同样，要从图形场景中删除项目，可以调用`removeItem`函数。

# 实现动画

要在 Python 中应用动画，我们将使用`QPropertyAnimation`类。PyQt 中的`QPropertyAnimation`类帮助创建和执行动画。`QPropertyAnimation`类通过操纵 Qt 属性（如小部件的几何形状、位置等）来实现动画。以下是`QPropertyAnimation`的一些方法：

+   `start()`: 该方法开始动画

+   `stop()`: 该方法结束动画

+   `setStartValue()`: 该方法用于指定动画的起始值

+   `setEndValue()`: 该方法用于指定动画的结束值

+   `setDuration()`: 该方法用于设置动画的持续时间（毫秒）

+   `setKeyValueAt()`: 该方法在给定值处创建关键帧

+   `setLoopCount()`: 该方法设置动画中所需的重复次数

# 显示 2D 图形图像

在本教程中，您将学习如何显示 2D 图形图像。我们假设您的计算机上有一个名为`scene.jpg`的图形图像，并将学习如何在表单上显示它。本教程的重点是了解如何使用 Graphics View 小部件来显示图像。

# 操作步骤...

显示图形的过程非常简单。您首先需要创建一个`QGraphicsScene`对象，该对象又利用`QGraphicsView`类来显示其内容。然后通过调用`QGraphicsScene`类的`addItem`方法向`QGraphicsScene`类添加图形项，包括图像。以下是在屏幕上显示 2D 图形图像的步骤：

1.  基于无按钮对话框模板创建一个新应用程序。

1.  将 Graphics View 小部件拖放到其中。

1.  将应用程序保存为`demoGraphicsView.ui`。表单将显示如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/bae96b96-83cd-4d38-9ed1-0185b3781174.png)

`pyuic5`命令实用程序将`.ui`（XML）文件转换为 Python 代码。生成的 Python 脚本`demoGraphicsView.py`可以在本书的源代码包中找到。

1.  创建一个名为`callGraphicsView.pyw`的 Python 脚本，导入代码`demoGraphicsView.py`，以调用用户界面设计，从磁盘加载图像，并通过 Graphics View 显示它。Python 脚本文件`callGraphicsView.pyw`将包括以下代码：

```py
import sys
from PyQt5.QtWidgets import QDialog, QApplication, QGraphicsScene, QGraphicsPixmapItem
from PyQt5.QtGui import QPixmap
from demoGraphicsView import *
class MyForm(QDialog):
    def __init__(self):
        super().__init__()
        self.ui = Ui_Dialog()
        self.ui.setupUi(self)
        self.scene = QGraphicsScene(self)
        pixmap= QtGui.QPixmap()
        pixmap.load("scene.jpg")
        item=QGraphicsPixmapItem(pixmap)
        self.scene.addItem(item)
        self.ui.graphicsView.setScene(self.scene)
if __name__=="__main__":
    app = QApplication(sys.argv)
    myapp = MyForm()
    myapp.show()
    sys.exit(app.exec_())
```

# 工作原理...

在此应用程序中，您正在使用 Graphics View 来显示图像。您向 Graphics View 小部件添加了一个图形场景，并添加了`QGraphicsPixmapItem`。如果要将图像添加到图形场景中，需要以`pixmap`项目的形式提供。首先，您需要将图像表示为`pixmap`，然后在将其添加到图形场景之前将其显示为`pixmap`项目。您需要创建`QPixmap`的实例，并通过其`load()`方法指定要通过其显示的图像。然后，通过将`pixmap`传递给`QGraphicsPixmapItem`的构造函数，将`pixmap`项目标记为`pixmapitem`。然后，通过`addItem`将`pixmapitem`添加到场景中。如果`pixmapitem`比`QGraphicsView`大，则会自动启用滚动。

在上面的代码中，我使用了文件名为`scene.jpg`的图像。请将文件名替换为您的磁盘上可用的图像文件名，否则屏幕上将不显示任何内容。

使用了以下方法：

+   `QGraphicsView.setScene`：此方法（self，`QGraphicsScene` scene）将提供的场景分配给`GraphicView`实例以进行显示。如果场景已经在视图中显示，则此函数不执行任何操作。设置场景时，将生成`QGraphicsScene.changed`信号，并调整视图的滚动条以适应场景的大小。

+   `addItem`：此方法将指定的项目添加到场景中。如果项目已经在不同的场景中，则首先将其从旧场景中移除，然后添加到当前场景中。运行应用程序时，将通过`GrahicsView`小部件显示`scene.jpg`图像，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/70652385-2de8-405b-b118-4b9f403460bf.png)

# 点击按钮使球移动

在本教程中，您将了解如何在对象上应用基本动画。本教程将包括一个按钮和一个球，当按下按钮时，球将开始向地面动画。

# 操作步骤...

为了制作这个教程，我们将使用`QPropertyAnimation`类。`QPropertyAnimation`类的`setStartValue()`和`setEndValue()`方法将用于分别定义动画需要开始和结束的坐标。`setDuration()`方法将被调用以指定每次动画移动之间的延迟时间（以毫秒为单位）。以下是应用动画的逐步过程：

1.  基于无按钮对话框模板创建一个新应用程序。

1.  将一个 Label 小部件和一个 Push Button 小部件拖放到表单上。

1.  将 Push Button 小部件的文本属性设置为`Move Down`。我们假设您的计算机上有一个名为`coloredball.jpg`的球形图像。

1.  选择其 pixmap 属性以将球图像分配给 Label 小部件。

1.  在 pixmap 属性中，从两个选项中选择 Resource 和 Choose File，选择 Choose File 选项，浏览您的磁盘，并选择`coloredball.jpg`文件。球的图像将出现在 Label 小部件的位置。

1.  将 Push Button 小部件的 objectName 属性设置为`pushButtonPushDown`，Label 小部件的 objectName 属性设置为`labelPic`。

1.  使用名称`demoAnimation1.ui`保存应用程序。应用程序将显示如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/d58c8775-5b6f-4b2f-8c3a-cdeefbcef278.png)

使用 Qt Designer 创建的用户界面存储在`.ui`文件中，这是一个需要转换为 Python 代码的 XML 文件。在应用`pyuic5`命令实用程序时，`.ui`文件将被转换为 Python 脚本。生成的 Python 脚本`demoAnimation1.py`可以在本书的源代码包中看到。

1.  将`demoAnimation1.py`脚本视为头文件，并将其导入到将调用其用户界面设计的文件中。

1.  创建另一个名为`callAnimation1.pyw`的 Python 文件，并将`demoAnimation1.py`代码导入其中：

```py
import sys
from PyQt5.QtWidgets import QDialog, QApplication
from PyQt5.QtCore import QRect, QPropertyAnimation
from demoAnimation1 import *
class MyForm(QDialog):
    def __init__(self):
        super().__init__()
        self.ui = Ui_Dialog()
        self.ui.setupUi(self)
        self.ui.pushButtonMoveDown.clicked.connect(self.
        startAnimation)
        self.show()
    def startAnimation(self):
        self.anim = QPropertyAnimation(self.ui.labelPic, 
        b"geometry")
        self.anim.setDuration(10000)
        self.anim.setStartValue(QRect(160, 70, 80, 80))
        self.anim.setEndValue(QRect(160, 70, 220, 220))
        self.anim.start()
if __name__=="__main__":
    app = QApplication(sys.argv)
    w = MyForm()
    w.show()
    sys.exit(app.exec_())
```

# 工作原理...

您可以看到，具有 objectName 属性`pushButtonMoveDown`的推送按钮小部件的 click()事件连接到`startAnimation`方法；当点击推送按钮时，将调用`startAnimation`方法。在`startAnimation`方法中，创建一个`QPropertyAnimation`类的对象并命名为`anim`。在创建`QPropertyAnimation`实例时，传递两个参数；第一个是要应用动画的标签小部件，第二个是定义要将动画应用于对象属性的属性。因为您想要对球的几何图形应用动画，所以在定义`QPropertyAnimation`对象时，将`b"geometry"`作为第二个属性传递。之后，将动画的持续时间指定为`10000`毫秒，这意味着您希望每隔 10,000 毫秒更改对象的几何图形。通过`setStartValue`方法，指定要开始动画的矩形区域，并通过调用`setEndValue`方法，指定要停止动画的矩形区域。通过调用`start`方法，启动动画；因此，球从通过`setStartValue`方法指定的矩形区域向下移动，直到达到通过`setEndValue`方法指定的矩形区域。

运行应用程序时，您会在屏幕上找到一个推送按钮和一个代表球图像的标签小部件，如下截图所示（左）。点击 Move Down 推送按钮后，球开始向地面动画，并在通过`setEndValue`方法指定的区域停止动画，如下截图所示（右）：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/36217d0c-f023-4596-9f9b-433a7f9502ac.png)

# 制作一个弹跳的球

在这个示例中，您将制作一个弹跳的球；当点击按钮时，球向地面掉落，触及地面后，它会反弹到顶部。在这个示例中，您将了解如何在对象上应用基本动画。这个示例将包括一个推送按钮和一个球，当按下推送按钮时，球将开始向地面动画。

# 如何做...

要使球看起来像是在弹跳，我们需要首先使其向地面动画，然后从地面向天空动画。为此，我们将三次调用`QPropertyAnimation`类的`setKeyValueAt`方法。前两次调用`setKeyValueAt`方法将使球从顶部向底部动画。第三次调用`setKeyValueAt`方法将使球从底部向顶部动画。在三个`setKeyValueAt`方法中提供坐标，以使球以相反方向弹跳，而不是从哪里来的。以下是了解如何使球看起来像在弹跳的步骤：

1.  基于没有按钮的对话框模板创建一个新的应用程序。

1.  将一个标签小部件和一个推送按钮小部件拖放到表单上。

1.  将推送按钮小部件的文本属性设置为`Bounce`。我们假设您的计算机上有一个名为`coloredball.jpg`的球形图像。

1.  要将球形图像分配给标签小部件，请选择其 pixmap 属性。

1.  在 pixmap 属性中，从两个选项`Choose Resource`和`Choose File`中选择`Choose File`选项，浏览您的磁盘，并选择`coloredball.jpg`文件。球的图像将出现在标签小部件的位置。

1.  将推送按钮小部件的 objectName 属性设置为`pushButtonBounce`，标签小部件的 objectName 属性设置为`labelPic`。

1.  将应用程序保存为`demoAnimation3.ui`。

应用程序将显示如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/f6f06312-aec8-4d84-864c-1635ffe30319.png)

使用 Qt Designer 创建的用户界面存储在`.ui`文件中，这是一个 XML 文件，需要转换为 Python 代码。在应用`pyuic5`命令实用程序时，`.ui`文件将被转换为 Python 脚本。生成的 Python 脚本`demoAnimation3.py`可以在本书的源代码包中找到。

1.  将`demoAnimation3.py`脚本视为头文件，并将其导入到您将调用其用户界面设计的文件中。

1.  创建另一个名为`callAnimation3.pyw`的 Python 文件，并将`demoAnimation3.py`代码导入其中。

```py
import sys
from PyQt5.QtWidgets import QDialog, QApplication
from PyQt5.QtCore import QRect, QPropertyAnimation
from demoAnimation3 import *
class MyForm(QDialog):
    def __init__(self):
        super().__init__()
        self.ui = Ui_Dialog()
        self.ui.setupUi(self)
        self.ui.pushButtonBounce.clicked.connect(self.
        startAnimation)
        self.show()
    def startAnimation(self):
        self.anim = QPropertyAnimation(self.ui.labelPic, 
        b"geometry")
        self.anim.setDuration(10000)
        self.anim.setKeyValueAt(0, QRect(0, 0, 100, 80));
        self.anim.setKeyValueAt(0.5, QRect(160, 160, 200, 180));
        self.anim.setKeyValueAt(1, QRect(400, 0, 100, 80));
        self.anim.start()
if __name__=="__main__":
    app = QApplication(sys.argv)
    w = MyForm()
    w.show()
    sys.exit(app.exec_())
```

# 工作原理...

您可以看到，具有 objectName 属性`pushButtonMoveDown`的 Push 按钮小部件的 click()事件与`startAnimation`方法连接在一起；当单击按钮时，将调用`startAnimation`方法。在`startAnimation`方法中，您创建一个`QPropertyAnimation`类的对象，并将其命名为`anim`。在创建`QPropertyAnimation`实例时，您传递两个参数：第一个是要应用动画的 Label 小部件，第二个是定义要将动画应用于对象属性的属性。因为您想要将动画应用于球的几何属性，所以在定义`QPropertyAnimation`对象时，将`b"geometry"`作为第二个属性传递。之后，您将动画的持续时间指定为`10000`毫秒，这意味着您希望每隔 10,000 毫秒更改对象的几何形状。通过`setKeyValue`方法，您指定要开始动画的区域，通过这种方法指定左上角区域，因为您希望球从左上角向地面掉落。通过对`setKeyValue`方法的第二次调用，您提供了球掉落到地面的区域。您还指定了掉落的角度。球将对角线向下掉落到地面。通过调用第三个`setValue`方法，您指定动画停止的结束值，在这种情况下是在右上角。通过对`setKeyValue`方法的这三次调用，您使球对角线向下掉落到地面，然后反弹回右上角。通过调用`start`方法，您启动动画。

运行应用程序时，您会发现 Push 按钮和 Label 小部件代表球图像显示在屏幕左上角，如下面的屏幕截图所示（左侧）。

单击 Bounce 按钮后，球开始沿对角线向下动画移动到地面，如中间屏幕截图所示，触地后，球反弹回屏幕的右上角，如右侧所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/b97a5f52-81a4-4e91-afde-843f7bfe0f4a.png)

# 根据指定的曲线使球动起来

创建一个具有所需形状和大小的曲线，并设置一个球在单击按钮时沿着曲线的形状移动。在这个示例中，您将了解如何实现引导动画。

# 如何做...

`QPropertyAnimation`类的`setKeyValueAt`方法确定动画的方向。对于引导动画，您在循环中调用`setKeyValueAt`方法。在循环中将曲线的坐标传递给`setKeyValueAt`方法，以使球沿着曲线动画。以下是使对象按预期动画的步骤：

1.  基于无按钮对话框模板创建一个新的应用程序。

1.  将一个 Label 小部件和一个 Push 按钮小部件拖放到表单上。

1.  将 Push 按钮小部件的文本属性设置为`Move With Curve`。

1.  假设您的计算机上有一个名为`coloredball.jpg`的球形图像，您可以使用其 pixmap 属性将此球形图像分配给 Label 小部件。

1.  在`pixmap`属性中，您会找到两个选项，选择资源和选择文件；选择选择文件选项，浏览您的磁盘，并选择`coloredball.jpg`文件。球的图像将出现在`Label`小部件的位置。

1.  将`Push Button`小部件的`objectName`属性设置为`pushButtonMoveCurve`，将`Label`小部件的`objectName`属性设置为`labelPic`。

1.  将应用程序保存为`demoAnimation4.ui`。应用程序将显示如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/0ab85891-3816-483b-9ede-704837a20332.png)

使用 Qt Designer 创建的用户界面存储在`.ui`文件中，是一个 XML 文件。通过应用`pyuic5`实用程序，将 XML 文件转换为 Python 代码。您可以在本书的源代码包中找到生成的 Python 代码`demoAnimation4.py`。

1.  将`demoAnimation4.py`脚本视为头文件，并将其导入到将调用其用户界面设计的文件中。

1.  创建另一个名为`callAnimation4.pyw`的 Python 文件，并将`demoAnimation4.py`代码导入其中：

```py
import sys
from PyQt5.QtWidgets import QDialog, QApplication
from PyQt5.QtCore import QRect, QPointF, QPropertyAnimation, pyqtProperty
from PyQt5.QtGui import QPainter, QPainterPath
from demoAnimation4 import *
class MyForm(QDialog):
    def __init__(self):
        super().__init__()
        self.ui = Ui_Dialog()
        self.ui.setupUi(self)
        self.ui.pushButtonMoveCurve.clicked.connect(self.
        startAnimation)
        self.path = QPainterPath()
        self.path.moveTo(30, 30)
        self.path.cubicTo(30, 30, 80, 180, 180, 170)
        self.ui.labelPic.pos = QPointF(20, 20)
        self.show()
    def paintEvent(self, e):
        qp = QPainter()
        qp.begin(self)
        qp.drawPath(self.path)
        qp.end()
    def startAnimation(self):
        self.anim = QPropertyAnimation(self.ui.labelPic, b'pos')
        self.anim.setDuration(4000)
        self.anim.setStartValue(QPointF(20, 20))
        positionValues = [n/80 for n in range(0, 50)]
        for i in positionValues:
            self.anim.setKeyValueAt(i,  
            self.path.pointAtPercent(i))
            self.anim.setEndValue(QPointF(160, 150))
            self.anim.start()
if __name__=="__main__":
    app = QApplication(sys.argv)
    w = MyForm()
    w.show()
    sys.exit(app.exec_())
```

# 工作原理...

首先，让曲线出现在屏幕上。这是将指导球动画的曲线；也就是说，它将作为动画的路径。您定义了`QPainterPath`类的实例并将其命名为`path`。您调用`QPainterPath`类的`moveTo`方法来指定路径或曲线的起始位置。调用`cubicTo`方法来指定球动画的曲线路径。

您会发现`Push Button`小部件的`objectName`属性为`pushButtonMoveCurve`的点击事件与`startAnimation`方法相连接；当单击`Push Button`小部件时，将调用`startAnimation()`方法。在`startAnimation`方法中，您创建了`QPropertyAnimation`类的对象并将其命名为`anim`。在创建`QPropertyAnimation`实例时，您传递了两个参数：第一个是要应用动画的`Label`小部件，第二个是定义要将动画应用于对象属性的属性。因为您想要将动画应用于球的位置，所以在定义`QPropertyAnimation`对象时，您将`b'pos'`作为第二个属性传递。之后，您将动画的持续时间指定为`4000`毫秒，这意味着您希望每`4000`毫秒更改球的位置。使用`QPropertyAnimation`类的`setStartValue()`方法，您指定了希望球进行动画的坐标。您设置了指定球需要沿着移动的值的`for`循环。您通过在`for`循环内调用`setKeyValue`方法来指定球的动画路径。因为球需要在路径中指定的每个点绘制，所以您通过调用`pointAtPercent()`方法并将其传递给`setKeyValueAt()`方法来设置球需要绘制的点。您还需要通过调用`setEndValue()`方法来设置动画需要停止的位置。

不久之后，您会指定动画的开始和结束位置，指定动画的路径，并调用`paintEvent()`方法来在路径的每一点重新绘制球。

运行应用程序后，您会在屏幕左上角（截图的左侧）找到`Push Button`小部件和代表球形图像的`Label`小部件，并在单击`Move With Curve`按钮后，球会沿着绘制的曲线开始动画，并在曲线结束的地方停止（截图的右侧）：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/4a89a80e-ad09-4699-bae1-03d9950497f4.png)
