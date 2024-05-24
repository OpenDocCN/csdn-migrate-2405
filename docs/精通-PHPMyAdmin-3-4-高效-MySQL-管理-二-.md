# 精通 PHPMyAdmin 3.4 高效 MySQL 管理（二）

> 原文：[`zh.annas-archive.org/md5/3B102B7D75B6F6D265E7C3CE6613ECC1`](https://zh.annas-archive.org/md5/3B102B7D75B6F6D265E7C3CE6613ECC1)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：改变数据和结构

数据并不是静态的，它经常发生变化。本章重点介绍了编辑和删除数据以及其支持结构——表和数据库。

这一章分为两个主要部分。第一部分涵盖了改变数据的所有方面。首先我们会看到如何编辑数据，即如何进入编辑模式，如何一次编辑多行数据，以及如何从内联编辑中受益。接下来我们会看到如何删除数据行，以及如何删除表和数据库。

第二部分解释了如何修改表的结构。我们将介绍如何向表中添加列；然后我们将探讨各种列类型，如`TEXT，BLOB，ENUM，DATE`和`BIT`列类型。最后，我们将介绍索引的管理。

# 改变数据

在本节中，我们将介绍编辑和删除数据的各种方法。

## 进入编辑模式

当我们浏览表或查看任何单表查询的搜索结果时，小图标和链接会出现在每个表行的左侧或右侧，如下面的截图所示：

![进入编辑模式](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_05_01.jpg)

可以使用铅笔形状的图标**(编辑)**来编辑行，使用红色图标**(删除)**来删除行。这些控件的确切形式和位置受以下因素的影响：

```sql
$cfg['PropertiesIconic'] = 'both';
$cfg['ModifyDeleteAtLeft'] = true;
$cfg['ModifyDeleteAtRight'] = false;

```

我们可以决定是在左侧显示它们，右侧显示它们，还是两侧都显示。`$cfg['PropertiesIconic']`参数可以有`TRUE, FALSE`或`both`的值。`TRUE`只显示图标，`FALSE`显示**编辑，内联编辑，复制**和**删除**（或它们的翻译等效），`both`显示图标和文本，如前面的截图所示。

每一行旁边的小复选框在本章后面的*多行编辑*和*删除多行*部分中有解释。

点击**编辑**图标或链接会带来以下面板，它与数据输入面板相似（除了下部分）。

![进入编辑模式](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_05_02.jpg)

在这个面板中，我们可以通过直接输入（或通过常规操作系统机制剪切和粘贴）来更改数据。我们也可以使用**重置**按钮恢复到原始内容。

默认情况下，下拉菜单设置为**保存**（以便我们对此行进行更改）和**返回到上一页**（以便我们可以继续编辑上一页结果页面上的另一行）。如果我们想要在点击**Go**后留在当前页面以保存然后继续编辑，我们可以选择**返回到此页面**。如果我们想要在保存当前行后插入另一行，我们只需在保存之前选择**插入另一行**。**插入为新行**选项（在**保存**选项下方）在本章后面的*复制数据行*部分中有解释。

### 使用 Tab 键移动到下一个字段

喜欢使用键盘的人可以使用*Tab*键来进入下一个字段。通常情况下，光标从左到右，从上到下移动，所以它会进入**Function**列中的字段（稍后会详细介绍）。然而，为了方便在 phpMyAdmin 中导航数据，正常的导航顺序已经改变。*Tab*键首先通过**Value**列中的每个字段，然后通过**Function**列中的每个字段。

### 使用箭头移动

另一种在字段之间移动的方法是使用*Ctrl* + *箭头*键。当屏幕上有许多字段时，这种方法可能比使用*Tab*键更容易。为了使其工作，`$cfg['CtrlArrowsMoving']`参数必须设置为`true`，这是默认值。

### 注意

在某些情况下，这种技术不能用于在字段之间移动。例如，Google Chrome 浏览器不支持*Ctrl* + *箭头*。另外，在启用了 Spaces 的 Mac OS X 10.5 上，*Ctrl* + *箭头*是在虚拟桌面之间切换的默认快捷键。

### 处理 NULL 值

如果表的结构允许在列中放置`NULL`值，那么在**Null**列中会出现一个小复选框。选择此复选框会在列中放置`NULL`值。每当在此列的**Value**中输入数据时，**Null**复选框会自动清除（这在启用 JavaScript 的浏览器中是可能的）。

在下面的屏幕截图中，我们修改了`author`表中**phone**列的结构，以允许`NULL`值（请参考本章的*编辑列属性*部分）。这里没有选择**Null**复选框：

![处理 NULL 值](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_05_03.jpg)

在选择**Null**框后，相应的数据被清除。

### 对值应用函数

MySQL 语言提供了一些函数，我们可以在保存之前应用到数据上。如果`$cfg['ShowFunctionFields']`设置为`TRUE`，则某些函数将出现在每个列旁边的下拉菜单中。

函数列表在`$cfg['Functions']`数组中定义。通常，这些数组的默认值位于`libraries/config.default.php`中。我们可以通过将所需的部分复制到`config.inc.php`中来更改它们。如果我们这样做，由于这些值可能会因版本而异，我们应该注意将我们的更改与新版本的值合并。某些数据类型的最常用函数首先显示在列表中。一些限制在`$cfg['RestrictColumnTypes']`和`$cfg['RestrictFunctions']`数组中定义。

如下面的屏幕截图所示，我们可以在保存此行时将**UPPER**函数应用于**title**列，将标题转换为大写字符：

![对值应用函数](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_05_04.jpg)

为了节省一些屏幕空间，可以通过将`$cfg['ShowFunctionFields']`设置为`FALSE`来禁用此功能。此外，**Function**列标题是可点击的，因此我们可以即时禁用此功能。

当功能被禁用时，要么通过点击，要么通过配置参数，会出现一个“显示：功能”链接，以便在单击时显示这个“功能”列，如下面的屏幕截图所示：

![对值应用函数](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_05_05.jpg)

**Type**列标题也可以通过点击或配置`$cfg['ShowFieldTypesInDataEditView']`来使用类似的功能。

### 数据行的复制

在数据维护过程中（用于永久复制或测试目的），我们经常需要生成一行的副本。如果在同一表中进行此操作，我们必须遵守唯一键的规则。

这是一个行复制的例子。我们的作者写了关于电影的第 2 卷书。因此，需要稍作更改的列是 ISBN、标题和页数。我们将现有行显示在屏幕上，更改这三列，并选择**插入为新行**，如下面的屏幕截图所示：

![数据行的复制](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_05_06.jpg)

当我们点击**Go**时，将创建另一行，带有修改后的信息，原始行保持不变，如下所示：

![数据行的复制](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_05_07.jpg)

存在一个快捷链接来执行相同的操作。在浏览表时，点击特定行的**复制**会带来该行的编辑面板，并选择**插入为新行**而不是**保存**。

## 多行编辑

多行编辑功能使我们能够在要编辑的行上使用复选框，并在**With selected**菜单中使用**Change**链接（或铅笔形图标）。**Check All / Uncheck All**链接也可以用于快速选中或取消选中所有复选框。我们还可以点击行数据的任何位置来激活相应的复选框。要选择一系列复选框，我们可以点击范围的第一个复选框，然后*Shift* + 点击范围的最后一个复选框。

![多行编辑](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_05_08.jpg)

单击**更改**后，出现包含所有选定行的编辑面板。在查看、比较和更改这些行的数据时，编辑过程可以继续进行。当我们用复选框标记一些行时，我们还可以对它们执行另外两个操作——**删除**（参见本章的*删除多行*部分）和**导出**（参见第六章)）。

## 编辑下一行

在具有整数列上的主键的表上可以进行顺序编辑。我们的`author`表符合这些条件。让我们看看当我们开始编辑具有**id**值**1**的行时会发生什么：

![编辑下一行](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_05_09.jpg)

编辑面板出现，我们可以编辑作者编号**1**。然而，在下拉菜单中，**编辑下一行**选项是可用的。如果选择了，下一个作者——第一个主键值大于当前主键值的作者——将可供编辑。

## 行内编辑

版本 3.4 引入了行内编辑，即在编辑时查看结果集的其他行。如果`$cfg['AjaxEnable']`设置为`true`，则可以使用`config.inc.php`或用户首选项。单击行的**行内编辑**显示以下对话框：

![行内编辑](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_05_10.jpg)

在编辑需要更改的列之后，我们单击**保存**。也可以使用**隐藏**链接中止更改。

## 删除数据

phpMyAdmin 的界面使我们能够删除以下数据：

+   单行数据

+   表的多行

+   表中的所有行

+   所有表中的所有行

### 删除单行

我们可以使用每行旁边的红色**删除**图标来删除行。如果`$cfg['Confirm']`的值设置为`TRUE`，则必须在执行之前确认每个 MySQL `DELETE`语句。这是默认设置，因为允许仅需一次点击即可删除行可能不明智！

确认的形式因浏览器执行 JavaScript 的能力而异。基于 JavaScript 的确认弹出窗将类似于以下截图：

![删除单行](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_05_11.jpg)

如果我们的浏览器已禁用 JavaScript，则会出现一个不同的面板。

实际的`DELETE`语句将使用所需的任何信息来确保仅删除预期的行。在我们的情况下，已定义了主键并在`WHERE`子句中使用了它。如果没有主键，将根据每列的值生成更长的`WHERE`子句。生成的`WHERE`子句甚至可能阻止`DELETE`操作的正确执行，特别是如果存在`TEXT`或`BLOB`列类型。这是因为用于将查询发送到 Web 服务器的 HTTP 事务可能会受到浏览器或服务器的长度限制。这是另一个为什么强烈建议定义主键的原因。

### 删除多行

让我们假设我们检查了一页的行，并决定一些行必须被删除。与其逐个使用**删除**链接或图标删除它们，有时在检查一组行时必须做出删除决定，`表`视图模式下的行旁边有复选框，如下面的截图所示：

![删除多行](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_05_12.jpg)

这些复选框与**选择的**菜单中的**删除**图标一起使用。确认屏幕将列出所有即将被删除的行。

### 删除表中的所有行

要完全删除表中的所有行（保持其结构不变），我们首先通过从导航面板中选择相关数据库来显示数据库**结构**页面。然后，我们使用与要清空的表位于同一行的**清空**图标或链接，如下所示：

![删除表中的所有行](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_05_13.jpg)

我们收到了确认`TRUNCATE`语句的消息（用于快速清空表的 MySQL 语句）。对于我们的练习，我们不会删除这些宝贵的数据！

### 注意

删除数据，无论是逐行删除还是清空表，都是永久性的操作。除非恢复备份，否则无法恢复。

### 删除多个表中的所有行

每个表名左侧都有一个复选框。我们可以选择一些表。然后，在**选择的操作**菜单中，选择**清空**操作，如下截图所示：

![删除多个表中的所有行](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_05_14.jpg)

当然，这个决定不能轻率地做出！

## 删除表

删除表会删除数据和表的结构。在`数据库`视图中，我们可以通过使用该表的红色**删除**图标来删除特定表。相同的机制也适用于删除多个表（使用下拉菜单和**删除**操作）。

## 删除数据库

我们可以通过转到`服务器`视图中的**数据库**页面，选择不需要的数据库旁边的复选框，然后点击**删除**链接来删除整个数据库（包括其所有表）：

![删除数据库](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_05_15.jpg)

默认情况下，`$cfg['AllowUserDropDatabase']`设置为`FALSE`。因此，该面板不允许非特权用户删除数据库，直到手动将此设置更改为`TRUE`为止。

为了帮助我们三思而后行，在删除数据库之前会出现一个特殊的消息——您即将销毁一个完整的数据库！

### 注意

包含所有用户和权限定义的数据库`mysql`非常重要。因此，即使对于管理员来说，该复选框也被禁用。

# 更改表结构

在开发应用程序时，由于新的或修改后的需求，关于数据结构的要求经常发生变化。开发人员必须通过审慎的表结构编辑来适应这些变化。本节探讨了更改表结构的主题。具体来说，它展示了如何向现有表中添加列和编辑列的属性。然后，我们基于这些概念引入了更多专业的列类型，并通过 phpMyAdmin 解释了它们的处理。最后，我们将涵盖索引管理的主题。

## 添加列

假设我们需要一个新列来存储书籍的语言，并且默认情况下，我们保存数据的书籍是用英语写的。我们称该列为**language**，它将包含由两个字符组成的代码（默认为**en**）。

在`book`表的`表`视图的**结构**页面中，我们可以找到**添加列**对话框。在这里，我们指定要添加多少个新列，以及它们将放在哪里。

表中新列的位置只在开发者的角度上才重要。通常我们会逻辑地分组列，这样我们可以在列的列表中更容易地找到它们。列的确切位置不会影响预期结果（查询的输出），因为无论表结构如何，这些结果都可以进行调整。通常，最重要的列（包括键）位于表的开头。然而，这是个人偏好的问题。

我们想把新列放在表的末尾。因此，我们选中相应的单选按钮，然后点击**执行**。

![添加列](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_05_16.jpg)

其他可能的选择是**在表的开头**和**之后**（在这种情况下，我们必须从下拉菜单中选择新列应该放在哪个列之后）。

我们看到了输入列属性的熟悉面板。我们填写它。然而，由于这次我们想输入一个默认值，所以我们进行了以下两个操作：

+   将**默认**下拉菜单从**无**更改为**如定义：**

+   输入默认值：**en**

然后我们点击**保存**。

![添加列](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_05_17.jpg)

### 垂直模式

前面的面板以垂直模式显示，因为`$cfg['DefaultPropDisplay']`的默认值为`3`。这意味着对于三列或更少，将使用垂直模式，对于三列以上，将自动选择水平模式。在这里，我们可以使用我们选择的数字。

如果我们将`$cfg['DefaultPropDisplay']`设置为`'vertical'`，则添加新列的面板（以及编辑列结构的面板）将始终以垂直顺序呈现。此参数还可以取值`'horizontal'`以强制水平模式。

## 编辑列属性

在**结构**页面上，我们可以对表进行进一步更改：

![编辑列属性](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_05_18.jpg)

此面板不允许对列进行所有可能的更改。它特别允许：

+   使用特定列上的**更改**链接更改一个列的结构

+   使用**删除**操作删除列

+   向现有**Primary**键添加列

+   在列上设置非唯一**索引**或**唯一**索引

+   设置**FULLTEXT**索引（仅当列类型允许时提供）

这些是一些可能在某些情况下有用的快速链接，但它们不能替代完整的索引管理面板。这两者都在本章中有解释。

我们可以使用复选框选择列。然后，使用适当的**选择**图标，我们可以使用**更改**编辑列，或者使用**删除**进行多列删除。**全选/取消全选**选项允许我们轻松地选中或取消选中所有框。

## TEXT 列类型

我们现在将探讨如何使用**TEXT**列类型和相关配置值来调整最佳的 phpMyAdmin 行为。首先，我们向**book**表中添加一个名为**description**的**TEXT**列。

有三个配置指令控制在**插入**或**编辑**模式下显示的**TEXT**列类型的文本区域的布局。每列的显示列数和行数由以下定义：

```sql
$cfg['TextareaCols'] = 40;
$cfg['TextareaRows'] = 15;

```

这默认情况下为**TEXT**列类型提供了工作空间，如下面的屏幕截图所示：

![TEXT 列类型](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_05_19.jpg)

设置只对文本区域施加了视觉限制，如果必要，浏览器会创建垂直滚动条。

### 注意

尽管**MEDIUMTEXT、TEXT**和**LONGTEXT**列类型可以容纳超过 32 KiB 的数据，但某些浏览器并不总是能够使用 HTML 提供的文本区域进行编辑。事实上，实验已经说服了 phpMyAdmin 开发团队，如果内容大于 32 KiB，产品将显示警告消息。该消息警告用户内容可能无法编辑。

最后一个配置指令`$cfg['LongtextDoubleTextarea']`只对**LONGTEXT**列类型有影响。默认值为`TRUE`，可以使编辑空间加倍。

## BLOB（二进制大对象）列类型

**BLOB**列类型通常用于保存二进制数据（如图像和声音），尽管 MySQL 文档暗示**TEXT**列类型也可以用于此目的。MySQL 5.1 手册中说：“在某些情况下，可能希望将媒体文件等二进制数据存储在 BLOB 或 TEXT 列中”。然而，另一句话：“BLOB 列被视为二进制字符串（字节字符串）”，似乎表明二进制数据应该真正存储在**BLOB**列中。因此，phpMyAdmin 的意图是使用**BLOB**列类型来保存所有二进制数据。

我们将在第十六章中看到，有特殊机制可进一步处理**BLOB**列类型，包括能够直接从 phpMyAdmin 中查看一些图像。

首先，我们向`book`表中添加一个名为**cover_photo**的**BLOB**列类型。如果现在浏览表，我们可以看到每个**BLOB**列类型的长度信息**[BLOB - 0B]**。

![BLOB（二进制大对象）列类型](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_05_20.jpg)

这是因为**Show BLOB**显示选项（还记得**选项**滑块吗？）默认情况下没有复选标记。因此，它阻止在浏览模式下显示**BLOB**内容。这种行为是有意的。通常，我们无法对以纯文本表示的二进制数据执行任何操作。

### 上传二进制内容

如果我们编辑一行，我们会看到**Binary do - not edit**警告和一个**浏览…**按钮。这个按钮的确切标题取决于浏览器。尽管不允许编辑，但我们可以轻松地将文本或二进制文件的内容上传到这个**blob**列中。

让我们使用**浏览**按钮选择一个图像文件，例如位于客户端工作站上的`phpMyAdmin/themes/pmahomme/img`目录的测试副本中的`logo_left.png`文件。现在点击**Go**。

![上传二进制内容](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_05_21.jpg)

我们需要记住一些上传大小的限制。首先，**blob**列的大小限制为 64 KiB，但在第十六章中，我们将更改此列的类型以容纳更大的图像。因此，phpMyAdmin 通过**Max: 64KiB**警告提醒我们这一限制。此外，PHP 本身可能存在限制（有关更多详细信息，请参阅第七章）。我们现在已经在特定行中上传了一张图片。

![上传二进制内容](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_05_22.jpg)

我们注意到**BLOB - 4.9KiB**是一个链接；如果需要，它允许我们下载任何二进制数据到我们的工作站。

如果我们为**Show BLOB Contents**显示选项打上复选标记，我们现在在**BLOB**列类型中看到以下内容：

![上传二进制内容](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_05_23.jpg)

### 注意

要真正在 phpMyAdmin 中查看图像，请参阅第十六章。

`$cfg['ProtectBinary']`参数控制编辑二进制列**(BLOB**和任何其他带有`binary`属性的列)时可以做什么。默认值**blob**阻止编辑**BLOB**列，但允许我们编辑 MySQL 标记为`binary`的其他列。值为`all`将甚至阻止编辑`binary`列。值为`FALSE`将不保护任何内容，因此允许我们编辑所有列。如果我们选择最后一个选项，我们会在此行的**编辑**面板中看到以下内容：

![上传二进制内容](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_05_24.jpg)

这个`BLOB`列类型的内容已经转换为十六进制，并且默认选择了**UNHEX**函数。我们可能不想以十六进制编辑这个图像数据，但这是在屏幕上安全表示二进制数据的最佳方式。这种十六进制表示的原因是，**Show binary contents as HEX display**选项（在**浏览**模式下）目前被标记。但我们没有标记这个选项；它被选中是因为`$cfg['DisplayBinaryAsHex']`指令默认为`TRUE`。

如果我们决定不标记这个选项，我们将看到这个图像的纯二进制数据：

![上传二进制内容](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_05_25.jpg)

这可能不是我们最喜欢的图像编辑器！实际上，即使我们在不触及**BLOB**列类型的情况下保存这一行，数据也可能会损坏。但是，将`$cfg['ProtectBinary']`设置为`FALSE`的可能性是存在的，因为一些用户在他们的**BLOB**列中放置文本，并且他们需要能够修改这些文本。这就是为什么 phpMyAdmin 可以配置为允许编辑**BLOB**列。

MySQL 的**BLOB**数据类型实际上与它们对应的**TEXT**数据类型类似。但是，我们应该记住**BLOB**没有字符集，而**TEXT**列类型有一个影响排序和比较的字符集。

## ENUM 和 SET 列类型

**ENUM**和**SET**列类型都旨在表示可能的值列表。区别在于用户可以从定义的值列表中选择一个值，**ENUM**，和使用**SET**可以选择多个值。对于**SET**，所有多个值都放入一个单元格；但是多个值并不意味着创建多行数据。

我们在`book`表中添加了一个名为**genre**的列，并将其定义为**ENUM**。目前，我们选择在值列表中放入简短的代码，并将其中一个值**F**作为默认值，如下面的屏幕截图所示：

![ENUM and SET column types](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_05_26.jpg)

在值列表中，我们必须将每个值用单引号括起来，与默认值字段不同。从 3.4.0 版本开始，针对`ENUM/SET`列的编辑器可用。使用此编辑器，我们无需费心将值用单引号括起来。单击**获取更多编辑空间**即可启用此编辑器：

![ENUM and SET column types](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_05_27.jpg)

在我们的设计中，这些值代表**幻想，儿童**和**小说**。但是，目前，我们希望看到界面对简短代码的行为。在**插入**面板中，我们现在看到一个单选框界面，如下面的屏幕截图所示：

![ENUM and SET column types](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_05_28.jpg)

如果我们决定有更多自描述的值，我们可以回到**结构**模式，并更改**genre**列的值定义。我们还必须将默认值更改为可能的值之一，以避免在尝试保存此列结构修改时收到错误消息。

![ENUM and SET column types](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_05_29.jpg)

使用修改后的值列表，**插入**面板现在如下所示：

![ENUM and SET column types](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_05_30.jpg)

请注意，单选按钮已被下拉列表取代，因为可能的值长度更大。

如果我们想要选择多个可能的值，我们必须将列类型更改为**SET**。可以使用相同的值列表。但是，使用浏览器的多值选择器（在 Windows 或 Linux 桌面上按住 Ctrl 键单击，在 Mac 上按住 Command 键单击），我们可以选择多个值，如屏幕截图所示：

![ENUM and SET column types](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_05_31.jpg)

### 注意

在规范化的数据结构中，我们只会在`book`表中存储**genre**代码，并依赖另一个表来存储每个代码的描述。在这种情况下，我们将不使用**SET**或**ENUM**。

## DATE，DATETIME 和 TIMESTAMP 列类型

我们可以使用普通字符列来存储日期或时间信息。但是**DATE，DATETIME**和**TIMESTAMP**对于此目的更有效。MySQL 检查内容以确保有效的日期和时间信息，并提供特殊函数来处理这些列。

### 日历弹出

作为额外的好处，phpMyAdmin 提供了一个日历弹出，方便数据输入。

我们将首先在`book`表中添加一个**DATE**列类型**—date_published—**。如果我们进入**插入**模式，现在应该会看到新列，我们可以在其中输入日期。还有一个**日历**图标可用。此图标会带来一个弹出窗口，与此**DATE**列类型同步。如果列中已经有值，则相应地显示弹出窗口。在我们的情况下，列中没有值，因此日历显示当前日期，如下面的屏幕截图所示：

![日历弹出](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_05_32.jpg)

小箭头方便地滚动月份和年份。点击我们想要的日期，将其传输到我们的**date_published**列。对于**DATETIME**或**TIMESTAMP**列类型，弹出窗口提供了编辑时间部分的功能。

### 注意

如果我们输入日期或时间值，如果我们的浏览器启用了 JavaScript，则会进行验证；不正确的值会用红色突出显示。

### 时间戳选项

从 MySQL 4.1.2 开始，有更多选项可以影响**TIMESTAMP**列类型。让我们在`book`表中添加一个名为**stamp**的**TIMESTAMP**类型的列。在**默认**下拉菜单中，我们可以选择**CURRENT_TIMESTAMP**；但是对于此练习，我们不会这样做。但是，在**属性**列中，我们选择**on update CURRENT_TIMESTAMP**。更多详细信息，请参阅[`dev.mysql.com/doc/refman/5.5/en/timestamp.html`](http://dev.mysql.com/doc/refman/5.5/en/timestamp.html)。

![TIMESTAMP 选项](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_05_33.jpg)

## 位列类型

MySQL 5.0.3 引入了真正的位列。它们在数据库中占用的空间与其定义中的位数相同。假设我们对每本书有以下三个信息，并且每个信息只能是真（1）或假（0）：

+   书是精装

+   书中包含 CD-ROM

+   书只有电子版可用

我们将使用一个单个**BIT**列来存储这三个信息。因此，我们在`book`表中添加一个长度为**3**（即 3 位）的列：

![位列类型](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_05_34.jpg)

为了构造并随后解释我们存储在此列中的值，我们必须以二进制方式思考，尊重列内每个位的位置。要指示一本书是精装，不包含 CD-ROM，并且仅以电子版形式提供，我们将使用值`101`。

phpMyAdmin 以二进制方式处理`BIT`列。例如，如果我们编辑一行并将值`101`设置为**some_bits**列的值，那么在保存时将发送以下查询：

```sql
UPDATE `marc_book`.`book` SET `some_bits` = b '101' 
WHERE `book`.`isbn` = '1-234567-89-0' LIMIT 1;

```

查询的突出部分显示该列实际上接收到了一个二进制值。在浏览时，精确值（在十进制中为`5` ——对于我们的目的来说是一个无意义的值）以其二进制形式`101`重新显示，这有助于解释每个离散的位值。有关位值表示法的更多详细信息，请参阅[`dev.mysql.com/doc/refman/5.5/en/bit-type.html`](http://dev.mysql.com/doc/refman/5.5/en/bit-type.html)。

## 管理索引

正确维护的索引对于数据检索速度至关重要。phpMyAdmin 具有许多索引管理选项，将在本节中介绍。

### 单列索引

我们已经看到**结构**面板通过一些链接（如**添加主键、添加索引**和**添加唯一索引**）提供了快速创建单列索引的方法。在列列表下方，有一个可用于管理索引的界面部分：

![单列索引](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_05_35.jpg)

此部分有链接可编辑或删除每个索引。在这里，**列**部分每个索引只列出一个列，我们可以看到整个列参与索引。这是因为在每个列名后面没有大小信息，与我们下一个示例中将看到的情况相反。

现在我们将在标题上添加一个索引。但是，我们希望限制此索引的长度，以减少磁盘上索引结构使用的空间。**在 1 列上创建索引**选项是合适的。因此，我们点击**Go**。在下一个屏幕中，我们指定索引详细信息如下：

![单列索引](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_05_36.jpg)

我们在此面板的选项中填写以下信息：

+   **索引名称：**我们发明的描述此索引目的的名称

+   **索引类型：**我们可以选择**INDEX**

+   **列：**我们选择用作索引的列，即**title**

+   **大小：**我们输入**30**而不是 100（列的完整长度），以节省表的物理部分中保存索引数据的空间

保存此面板后，我们可以从以下屏幕截图中确认索引已创建，并且不覆盖**title**列的整个长度：

![单列索引](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_05_37.jpg)

### 多列索引和索引编辑

在下一个示例中，我们假设在将来的应用程序中，我们将需要找到特定作者写的特定语言的书。将**author_id**索引扩展，添加**language**列到其中是有意义的。

我们点击包含**author_id**索引的行上的**Edit**链接（小铅笔图标），这将显示此索引的当前状态。界面上有空间可以向此索引添加另一列。如果需要添加多于一列，我们可以使用**Add to index 1 column(s)**功能。在选择器中，我们选择**language**。这次我们不需要输入大小，因为整个列将被用于索引。为了更好的文档记录，我们更改**Index name (author_language** 为适当的名称，如下图所示：

![多列索引和索引编辑](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_05_38.jpg)

我们保存这个索引修改。在索引列表中，我们可以确认我们的索引修改。

### 全文索引

这种特殊类型的索引允许进行全文搜索。它仅支持`MyISAM`表的**VARCHAR**和**TEXT**列类型，但 MySQL 5.6 也应该为`InnoDB`提供此功能。我们可以在列列表中使用**Add FULLTEXT index**链接，或者转到索引管理面板，并在下拉菜单中选择**FULLTEXT**。

### 使用 EXPLAIN 优化索引

在这一部分，我们想要获取有关 MySQL 用于特定查询的索引以及没有定义索引的性能影响的一些信息。

假设我们想使用以下查询：

```sql
SELECT *
FROM `book`
WHERE author_id = 2 AND language = 'es'

```

我们想知道，哪些由`id`为`2`的作者写的书是用`es`语言——我们的西班牙语的代码。

要输入此查询，我们可以使用数据库或表菜单中的**SQL**选项卡，或者 SQL 查询窗口（参见第十一章）。我们在查询框中输入此查询，然后点击**Go**。目前查询是否找到任何结果并不重要。

### 注意

您可以通过按照第八章中的解释来获得相同的查询，以便搜索**author_id 2**和语言**es**。

![使用 EXPLAIN 优化索引](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_05_39.jpg)

我们现在将使用**[Explain SQL]**链接来获取有关此查询使用了哪个索引（如果有的话）的信息。

![使用 EXPLAIN 优化索引](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_05_40.jpg)

我们可以看到**EXPLAIN**命令已经传递给 MySQL，告诉我们使用的**key**是**author_language**。因此，我们知道这个索引将用于这种类型的查询。如果这个索引不存在，结果将会有很大不同。

![使用 EXPLAIN 优化索引](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_05_41.jpg)

这里，**key (NULL)** 和 **type (ALL)** 意味着没有使用索引，需要检查所有行以找到所需的数据。根据总行数的不同，这可能会严重影响性能。我们可以通过检查 phpMyAdmin 在每个结果页面上显示的查询时间 **(Query took x sec)** 来确定确切的影响，并将其与有无索引进行比较。然而，如果我们只有有限的测试数据，与生产中的真实表相比，时间上的差异可能是微不足道的。有关`EXPLAIN`输出格式的更多详细信息，请参阅[`dev.mysql.com/doc/refman/5.5/en/explain-output.html`](http://dev.mysql.com/doc/refman/5.5/en/explain-output.html)。

### 检测索引问题

为了帮助用户维护最佳的索引策略，phpMyAdmin 尝试检测一些常见的索引问题。例如，让我们访问`book`表并在**isbn**列上添加一个索引。当我们显示这个表的结构时，我们会得到如下截图所示的警告：

![检测索引问题](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_05_42.jpg)

这里的意图是在考虑整个表时警告我们关于索引结构的低效性。我们不需要在同一列上有两个索引。

# 总结

本章讨论了数据更改的概念，例如：

+   编辑数据

+   包括`NULL`列和使用*Tab*键

+   对值应用函数

+   复制数据行

+   删除数据、表和数据库

我们还概述了结构更改技术，例如：

+   如何添加列，包括特殊的列类型，如 TEXT、BLOB、ENUM 和 SET

+   如何使用日历弹出窗口来处理 DATE、DATETIME 和 TIMESTAMP 列类型

+   如何将二进制数据上传到 BLOB 列

+   如何管理索引（多列和全文），并从 MySQL 获取关于特定查询中使用了哪些索引的反馈

在下一章中，我们将学习如何导出表的结构和数据以备份，或者用作连接到另一个应用程序的网关。


# 第六章：导出结构和数据（备份）

保持良好的备份对于项目至关重要。备份包括最新的备份和在开发和生产阶段进行的中间快照。phpMyAdmin 的导出功能可以生成备份，并且还可以用于将数据发送到其他应用程序。

### 注意

请注意，phpMyAdmin 的导出功能可以按需生成备份，强烈建议实施自动和脚本化的备份解决方案，定期进行备份。实施这样的解决方案的确切方式取决于服务器的操作系统。

# 转储，备份和导出

让我们首先澄清一些词汇。在 MySQL 文档中，您会遇到术语**dump**，在其他应用程序中是**备份**或**导出**。在 phpMyAdmin 上下文中，所有这些术语都具有相同的含义。

MySQL 包括**mysqldump**-一个命令行实用程序，可用于生成导出文件。但并非每个主机提供商都提供命令行实用程序所需的 shell 访问权限。此外，从 Web 界面中访问导出功能更加方便。这就是为什么 phpMyAdmin 提供了比 mysqldump 更多导出格式的导出功能。本章将重点介绍 phpMyAdmin 的导出功能。

在开始导出之前，我们必须清楚地了解导出的预期目标。以下问题可能有所帮助：

+   我们需要完整的数据库还是只需要一些表？

+   我们只需要结构，只需要数据，还是两者都需要？

+   将使用哪个实用程序来导入数据？

+   我们只需要数据的子集吗？

+   预期导出的大小是多少，我们和服务器之间的链接速度是多少？

## 导出的范围

当我们从 phpMyAdmin 点击**导出**链接时，我们可能处于以下视图或上下文之一-`数据库`视图，`表`视图或`服务器`视图（稍后在[第十九章]中更多了解此内容））。根据当前上下文，导出的范围将是完整的数据库，单个表，甚至是多个数据库，如`服务器`视图的情况。我们将首先解释数据库导出和所有相关的导出类型。然后我们将继续表和多数据库导出，强调这些导出模式的区别。

# 导出数据库

在`数据库`视图中，点击**导出**链接。自 3.4.0 版本以来，默认的导出面板如下截图所示：

![导出数据库](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_06_01.jpg)

默认情况下，`$cfg['Export']['method']`设置为`'quick'`，`$cfg['Export']['format']`设置为`'sql'`。可用性测试表明，导出的最常见目标是以 SQL 格式生成完整的备份并将其保存在我们的工作站上；只需点击**Go**即可完成。

`$cfg['Export']['method']`的其他值是`'custom'`，它将显示详细的导出选项，以及`'custom-no-form'`，它也会显示详细选项，但不会显示选择快速导出的可能性-这是 3.4.0 版本之前的行为。

在自定义模式下，会显示子面板。**表，输出**和**格式**子面板占据页面顶部。**特定格式选项**子面板会变化，以显示所选择的导出格式的选项。以下截图显示了 SQL 格式面板：

![导出数据库](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_06_02.jpg)

## 表子面板

该子面板包含一个表选择器，我们可以从中选择要导出的表。默认情况下，所有表都被选中，我们可以使用**全选/取消全选**链接来更改我们的选择。

## 输出子面板

默认行为是通过 HTTP 传输导出文件（选择**将输出保存到文件**单选按钮）。这会触发浏览器中的**保存**对话框，最终将文件保存在我们的本地机器上。另一种选择是选择**以文本形式查看输出**，这可以作为测试过程，前提是导出的数据是合理大小。

### 文件名模板

建议文件的名称将遵循**文件名模板**字段。在此模板中，我们可以使用特殊的**@SERVER@、@DATABASE@**和**@TABLE@**占位符。这些占位符将被当前服务器、数据库或表名（对于单表导出）替换。请注意，在这些单词之前和之后都有一个"at sign"字符。我们还可以使用 PHP `strftime`函数中的任何特殊字符；这对于根据当前日期或小时生成导出文件非常有用。最后，我们可以放置任何其他字符串（不是`strftime`特殊字符的一部分），这些字符串将被文字使用。文件扩展名根据导出类型生成。在这种情况下，它将是`.sql`。以下是模板的一些示例：

+   `@DATABASE@`将生成`marc_book.sql`

+   `@DATABASE@-%Y%m%d`将给出`marc_book-20110920.sql`

激活**将来用于导出**选项会将输入的模板设置存储到 cookie 中（用于数据库、表或服务器导出），并在下次使用相同类型的导出时将它们带回来。

默认模板是可配置的，通过以下参数：

```sql
$cfg['Export']['file_template_table'] = '@TABLE@';
$cfg['Export']['file_template_database'] = '@DATABASE@';
$cfg['Export']['file_template_server'] = '@SERVER@';

```

可能的占位符，如`@DATABASE@`与窗口标题中使用的占位符相同，并在`Documentation.html`，FAQ 6.27 中描述。

### 选择字符集

我们可以为导出的文件选择确切的字符集。phpMyAdmin 会验证重新编码的条件是否满足。对于实际的数据重新编码，Web 服务器的 PHP 组件必须支持`iconv`或`recode`模块。`$cfg['RecodingEngine']`参数指定实际的重新编码引擎，选择包括`none, auto, iconv`和`recode`。如果设置为`auto`，phpMyAdmin 将首先尝试`iconv`模块，然后尝试`recode`模块。如果设置为`none`，字符集对话框将不会显示。

### 汉字支持

如果 phpMyAdmin 检测到使用日语，它会检查 PHP 是否支持`mb_convert_encoding()`多字节字符串函数。如果支持，导出和导入页面以及查询框上会显示额外的单选按钮，这样我们就可以在`EUC-JP`和`SJIS`日语编码之间进行选择。

以下是从**导出**页面中获取的示例：

![Kanji support](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_06_03.jpg)

### 压缩

为了节省传输时间并获得更小的导出文件，phpMyAdmin 可以压缩为 ZIP、GZIP 或 BZIP2 格式。只有在 PHP 服务器编译时分别使用了`--with-zlib`（用于 ZIP 和 GZIP）或`--with-bz2`（用于 BZ2）配置选项，才会提供这些格式。以下参数控制在面板中呈现哪些压缩选项：

```sql
$cfg['ZipDump'] = TRUE;
$cfg['GZipDump'] = TRUE;
$cfg['BZipDump'] = TRUE;

```

安装 phpMyAdmin 的系统管理员可以选择将所有这些参数设置为`FALSE`，以避免大量用户同时压缩其导出所带来的潜在开销。这种情况通常比所有用户同时传输未压缩文件带来更多的开销。

在较旧的 phpMyAdmin 版本中，压缩文件是在 Web 服务器内存中构建的。由此引起的一些问题包括：

+   文件生成取决于分配给运行 PHP 脚本的内存限制。

+   在生成和压缩文件的过程中，没有传输发生。因此，用户倾向于认为操作没有进行，或者发生了崩溃。

+   大型数据库的压缩是不可能实现的。

`$cfg['CompressOnFly']`参数（默认设置为`TRUE`）被添加以生成（对于 GZIP 和 BZIP2 格式）一个包含更多标头的压缩文件。现在，传输几乎立即开始。文件以较小的块发送，因此整个过程消耗的内存要少得多。这样做的缺点是生成的文件稍微更大。

## 导出格式

我们现在将讨论可以在**格式**子面板中选择的格式（以及选择后可用的选项）。

### 注意

即使我们可以导出多种格式，但只有其中一些格式可以使用 phpMyAdmin 导入。

### SQL

SQL 格式很有用，因为它创建了标准的 SQL 命令，可以在任何 SQL 服务器上运行。

如果选中**显示注释**复选框，则导出文件中将包含注释。导出的第一部分包括注释（以`--`字符开头），详细说明了创建文件的实用程序（和版本），日期和其他环境信息。然后我们看到每个表的`CREATE`和`INSERT`查询。

phpMyAdmin 在导出文件中生成与 ANSI 兼容的注释。这些注释以`--`开头。它们有助于在其他 ANSI SQL 兼容系统上重新导入文件。

SQL 选项用于定义导出将包含的确切信息。下面的屏幕截图显示了一般的 SQL 选项：

![SQL](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_06_04.jpg)

一般的 SQL 选项有：

+   **附加自定义头注释：**我们可以为此导出添加自己的注释（例如，**每月备份**），这些注释将显示在导出标头中（在 PHP 版本号之后）。如果注释有多行，我们必须使用特殊字符`\n`来分隔每一行。

+   **显示外键关系：**在第十章中，我们将看到即使是在`MyISAM`存储引擎下的表，也可以定义关系；此选项将导出这些关系的定义作为注释。这些不能直接导入，但作为可读的表信息仍然很有价值。

+   **显示 MIME 类型：**这会添加信息（以 SQL 注释的形式），描述哪些 MIME 类型已与列关联。第十六章进一步解释了这一点。

+   **将导出封装在事务中：**从 MySQL 4.0.11 开始，我们可以使用`START TRANSACTION`语句。这个命令与在开头使用`SET AUTOCOMMIT=0`和在结尾使用`COMMIT`结合在一起，要求 MySQL 在一个事务中执行导入（当我们重新导入此文件时），确保所有更改都作为一个整体完成。

+   **禁用外键检查：**在导出文件中，我们可以添加`DROP TABLE`语句。但是，通常如果表在外键约束中被引用，就无法删除该表。此选项通过在导出文件中添加`SET FOREIGN_KEY_CHECKS=0`来覆盖验证。此覆盖仅在导入的持续时间内有效。

+   **数据库系统或旧的 MySQL 服务器以最大化输出兼容性：**这让我们选择要导出的 SQL 的类型。我们必须了解我们打算导入此文件的系统。选择包括**MySQL 3.23，MySQL 4.0，ORACLE**和**ANSI**。

我们可能想要导出结构、数据或两者；这是通过**转储表**选项执行的。选择**结构**会生成包含`CREATE`查询的部分，选择**数据**会生成`INSERT`查询。

如果我们选择**结构**，则会出现**对象创建选项**子面板，如下面的屏幕截图所示：

![SQL](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_06_05.jpg)

结构选项有：

+   **添加 DROP TABLE / VIEW / PROCEDURE / FUNCTION / EVENT：** 在每个`CREATE`语句之前添加`DROP ... IF EXISTS`语句，例如`DROP TABLE IF EXISTS `author``;。这样，我们可以确保导出文件在已经存在相同元素的数据库上执行，更新其结构但销毁先前元素的内容。

+   **添加 CREATE PROCEDURE / FUNCTION / EVENT：** 这包括在此数据库中找到的所有存储过程、函数和事件定义，在导出中包含它们。

+   **创建表选项/如果不存在：** 将`IF NOT EXISTS`修饰符添加到`CREATE TABLE`语句中，避免在表已经存在时导入时出现错误。

+   **创建表选项/自动增量：** 将表中的自动增量信息放入导出中，确保表中插入的行将获得下一个确切的自动增量 ID 值。

+   **用反引号括起表名和字段名：** 在 MySQL 世界中，反引号是保护可能包含特殊字符的表和列名的常规方式。在大多数情况下，这是有用的。但是，如果目标服务器（导出文件将被导入的地方）运行不支持反引号的 SQL 引擎，则不建议使用反引号。

以下屏幕截图显示了与**数据**导出相关的选项：

![SQL](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_06_06.jpg)

**数据**部分提供的选项包括：

+   **INSERT DELAYED 语句：** 将`DELAYED`修饰符添加到`INSERT`语句中。这会加速`INSERT`操作，因为它被排队到服务器，服务器在表不在使用时执行它。这是 MySQL 的非标准扩展，仅适用于`MyISAM，MEMORY`和`ARCHIVE`表。

+   **INSERT IGNORE 语句：** 通常，在导入时，我们不能为唯一键插入重复的值，因为这会中止插入操作。此选项将`IGNORE`修饰符添加到`INSERT`和`UPDATE`语句中，从而跳过生成重复键错误的行。

+   **在转储数据时使用的函数：** 选择有**INSERT，UPDATE**和**REPLACE**。其中最著名的是默认的**INSERT**—使用`INSERT`语句导入我们的数据。但是，在导入时，我们可能会遇到这样的情况：表已经存在并包含有价值的数据，我们只想更新当前导出表中的列。**UPDATE**生成类似下面这行代码的语句，在找到相同的主键或唯一键时更新一行：

```sql
UPDATE `author` SET `id` = 1, `name` = 'John Smith', `phone` = '111-1111' WHERE `id` = '1';

```

第三种可能性，**REPLACE**，生成诸如`REPLACE INTO `author` VALUES (1, 'John Smith', '111-1111');`的语句。这类似于对新行进行插入操作，并根据主键或唯一键更新现有行。

+   **插入数据时使用的语法：** 这里有几种选择。在每个语句中包含列名会使生成的文件更大，但在各种 SQL 系统上更具可移植性，并且更易于文档化。使用一个语句插入多行比使用多个`INSERT`语句更快，但不太方便，因为它使得读取结果文件更加困难。它还会生成一个较小的文件，但是该文件的每一行本身都不可执行，因为每一行都没有`INSERT`语句。如果无法在一次操作中导入完整的文件，则无法使用文本编辑器拆分文件并逐块导入。

+   **创建查询的最大长度：** 为**扩展插入**生成的单个`INSERT`语句可能会变得太大并引起问题。因此，我们为此语句的长度设置了字符数的限制。

+   **以十六进制表示法转储二进制列：**此选项使 phpMyAdmin 以`0x`格式对`BLOB`列的内容进行编码。这种格式很有用，因为根据将用于处理导出文件的软件（例如文本编辑器或邮件程序），处理包含 8 位数据的文件可能会有问题。但是，使用此选项将产生大小为原始大小两倍的`BLOB`列类型的导出。

+   **在 UTC 中转储时间戳列：**如果导出文件将被导入到位于不同时区的服务器上，则这将很有用。

### CSV

这种格式被许多程序理解，您可能会发现它在交换数据时很有用。请注意，这是一种仅包含数据的格式——这里没有 SQL 结构。

![CSV](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_06_07.jpg)

可用的选项有：

+   **用逗号分隔的列：**我们在这里放一个逗号，这意味着每个列后面都会放一个逗号。默认值来自`$cfg['Export']['csv_separator']`。

+   **用以下字符包围的列：**我们在这里放一个包围字符（双引号），以确保不会将包含终止字符（逗号）的列视为两列。默认值来自`$cfg['Export']['csv_enclosed']`。

+   **用以下字符转义的列：**如果导出生成器在列中找到**用以下字符包围**字符，那么该字符将被放在它之前以保护它。例如，`"John \"The Great\"Smith"`。默认值来自`$cfg['Export']['csv_escaped']`。

+   **以以下字符结尾的行：**这决定了每行的结束字符。我们应该根据将操作结果导出文件的操作系统使用适当的行分隔符。此选项的默认值来自`$cfg['Export']['csv_terminated']`参数，默认情况下包含`'AUTO'`。`'AUTO'`值会在浏览器的操作系统为 Windows 时产生值`\r\n`，否则产生值`\n`。但是，如果导出文件打算用于具有不同操作系统的机器，则这可能不是最佳选择。

+   **用以下字符串替换 NULL：**这确定了在导出文件中找到任何`NULL`值的列中占据位置的字符串。

+   **删除列中的回车/换行字符：**由于列可能包含回车或换行字符，这将确定是否应从导出的数据中删除这些字符。

+   **将列名放在第一行：**这会获取有关每列含义的一些信息。一些程序将使用此信息来命名列。在这个练习中，我们选择了这个选项。

最后，我们选择`author`表。

点击**Go**会生成一个包含以下行的文件：

```sql
"id","name","phone"
"1","John Smith","+01 445 789-1234"
"2","Maria Sunshine","+01 455 444-5683"

```

### Microsoft Excel 的 CSV

这种导出模式生成了一个专门为 Microsoft Excel 格式化的 CSV 文件（使用分号而不是逗号）。我们可以选择确切的 Microsoft Excel 版本，如下面的屏幕截图所示：

![Microsoft Excel 的 CSV](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_06_08.jpg)

### PDF

通过导出为 PDF，可以创建表的 PDF 报告。此功能始终会生成一个文件。自 phpMyAdmin 3.4.7 以来，我们还可以一次性导出完整数据库或多个表。我们可以为此报告添加标题，并且它也会自动分页。在这种导出格式中，`book`表中的非文本`(BLOB)`数据将被丢弃。

在这里，我们在`author`表上进行测试，要求使用"The authors"作为标题。PDF 很有趣，因为它固有的矢量性质——结果可以被放大。让我们来看一下从 Adobe Reader 中看到的生成的报告：

![PDF](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_06_09.jpg)

### Microsoft Word 2000

这种导出格式直接生成一个适用于所有理解 Word 2000 格式的软件的`.doc`文件。我们发现与 Microsoft Excel 导出中类似的选项，还有一些其他选项。我们可以独立导出表的**结构**和**数据**。

![Microsoft Word 2000](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_06_10.jpg)

请注意，对于这种格式和 Excel 格式，我们可以选择多个表进行一次导出。但是，如果其中一个表具有非文本数据，将会出现不愉快的结果。以下是`author`表格的结果：

![Microsoft Word 2000](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_06_11.jpg)

### LaTeX

**LaTeX**是一种排版语言。phpMyAdmin 可以生成一个代表表的结构和/或数据的`.tex`文件，以横向表格的形式呈现。

### 注意

请注意，这个文件不能直接查看，必须进一步处理或转换为预期的最终媒体。

可用的选项有：

| 选项 | 描述 |
| --- | --- |
| **包括表标题** | 在表格输出中显示标题 |
| **结构** 和 **数据** | 请求结构、数据或两者的熟悉选择 |
| **表标题** | 要放在第一页上的标题 |
| **表标题（继续）** | 要放在每一页上的标题 |
| **显示外键关系、注释、MIME 类型** | 我们希望作为输出的其他结构信息。如果 phpMyAdmin 配置存储已经就位，这些选择是可用的 |

### XML

这种格式在数据交换中非常流行。我们可以选择要导出的数据定义元素（如函数、过程、表、触发器或视图）。接下来是`author`表格的输出。

```sql
<?xml version="1.0" encoding="utf-8"?>
<!--
- phpMyAdmin XML Dump
- version 3.4.5
- http://www.phpmyadmin.net
-
- Host: localhost
- Generation Time: Sep 16, 2011 at 03:18 PM
- Server version: 5.5.13
- PHP Version: 5.3.8
-->
<pma_xml_export version="1.0" >
<!--
- Structure schemas
-->
<pma:structure_schemas>
<pma:database name="marc_book" collation="latin1_swedish_ci" charset="latin1">
<pma:table name="author">
CREATE TABLE `author` (
`id` int(11) NOT NULL,
`name` varchar(30) NOT NULL,
`phone` varchar(30) DEFAULT NULL,
PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
</pma:table>
</pma:database>
</pma:structure_schemas>
<!--
- Database: 'marc_book'
-->
<database name="marc_book">
<!-- Table author -->
<table name="author">
<column name="id">1</column>
<column name="name">John Smith</column>
<column name="phone">+01 445 789-1234</column>
</table>
<table name="author">
<column name="id">2</column>
<column name="name">Maria Sunshine</column>
<column name="phone">333-3333</column>
</table>
</database>
</pma_xml_export>

```

### 打开文档电子表格

这种电子表格格式是开放文档（[`en.wikipedia.org/wiki/OpenDocument`](http://en.wikipedia.org/wiki/OpenDocument)）的一个子集，它在`OpenOffice.org`办公套件中非常流行。我们需要选择一个要导出的表，以便有一个连贯的电子表格。以下截图显示了我们的`author`表格，导出为名为`author.ods`的文件，并随后在 OpenOffice 中查看：

![打开文档电子表格](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_06_12.jpg)

### 打开文档文本

这是开放文档标准的另一个子集，这次是面向文本处理的。我们的`author`表格现在已经从 OpenOffice 中导出并查看。

![打开文档文本](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_06_13.jpg)

### YAML

**YAML**代表**YAML 不是标记语言**。YAML 是一种人类可读的数据序列化格式；它的官方网站是[`www.yaml.org`](http://www.yaml.org)。这种格式在 phpMyAdmin 中没有我们可以选择的选项。以下是`author`表格的 YAML 导出：

```sql
1:
id: 1
name: John Smith
phone: +01 445-789-1234
2:
id: 2
name: Maria Sunshine
phone: 333-3333

```

### CodeGen

这个选择可能有一天会支持与代码开发相关的许多格式。目前，它可以导出 NHibernate **对象关系映射（ORM）**格式。更多详情，请参阅[`en.wikipedia.org/wiki/Nhibernate`](http://en.wikipedia.org/wiki/Nhibernate)。

### Texy!文本

**Texy!**是一个带有自己简化语法的格式化工具（[`texy.info/en/`](http://texy.info/en/)）。以下是以这种格式导出的示例代码：

```sql
===Database marc_book
== Table structure for table author
|------
|Field|Type|Null|Default
|------
|//**id**//|int(11)|Yes|NULL
|name|varchar(30)|Yes|NULL
|phone|varchar(30)|Yes|NULL
== Dumping data for table author
|1|John Smith|+01 445 789-1234
|2|Maria Sunshine|333-3333

```

### PHP 数组

在 PHP 中，关联数组可以保存文本数据；因此，可以使用 PHP 数组导出格式。以下是`author`表格的 PHP 数组导出：

```sql
<?php
// marc_book.author
$author = array(
array('id'=>1,'name'=>'John Smith','phone'=>'+1 445 789-1234'),
array('id'=>2,'name'=>'Maria Sunshine','phone'=>'333-3333')
);

```

### MediaWiki 表格

MediaWiki（[`www.mediawiki.org/wiki/MediaWiki`](http://www.mediawiki.org/wiki/MediaWiki)）是一个流行的维基包，支持广泛使用的维基百科。这个维基软件实现了一种格式化语言，可以用表格格式描述数据。在 phpMyAdmin 中选择这种导出格式会产生一个文件，可以粘贴到我们正在编辑的维基页面上。

### JSON

JavaScript 对象表示法（[`json.org`](http://json.org)）是一种在网络世界中流行的数据交换格式。以这种格式导出`author`表格的代码如下所示：

```sql
/**
Export to JSON plugin for PHPMyAdmin
@version 0.1
*/
/* Database 'marc_book' */
/* marc_book.author */
[{"id": 1,"name": "John Smith","phone": "+01 445 789-1234"}, {"id": 2,"name": "Maria Sunshine","phone": "333-3333"}]

```

# 导出表格

`表`视图中的**导出**链接会显示特定表的导出子面板。它类似于数据库导出面板，但没有表选择器。然而，在**输出**子面板之前，还有一个用于分割导出（行）的额外部分，如下所示：

![导出表格](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_06_14.jpg)

## 分割文件导出

对话框中包含的**行数**和**开始行**部分使我们能够将表分成多个部分。根据确切的行大小，我们可以尝试各种值来找到要查找的行数以及在 Web 服务器中达到内存或执行时间限制之前可以放入单个导出文件中的行数。然后，我们可以为我们的导出文件使用名称，例如`book00.sql`和`book01.sql`。如果我们决定导出所有行，我们只需选择**转储所有行**单选按钮。

# 有选择地导出

在 phpMyAdmin 界面的各个位置，我们可以导出我们看到的结果，或者选择要导出的行。我们将研究导出表的选定部分的各种方法。

## 导出部分查询结果

当从 phpMyAdmin 显示结果（这里是查询要求显示**作者 ID 为 2**的书籍结果）时，页面底部会出现一个**导出**链接。

![导出部分查询结果](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_06_15.jpg)

单击此链接会弹出一个特殊的导出面板，其中包含顶部的查询以及其他表导出选项。通过此面板生成的导出将仅包含此结果集中的数据。

### 注意

单表查询的结果可以以所有可用格式导出，而多表查询的结果可以以除 SQL 之外的所有格式导出。

## 导出和复选框

每当我们看到结果（例如浏览或搜索时），我们可以勾选我们想要的行旁边的复选框，然后使用**选择的内容：导出**图标或链接生成一个仅包含这些行的部分导出文件。

![导出和复选框](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_06_16.jpg)

# 导出多个数据库

任何用户都可以在一次操作中导出他/她有权限访问的数据库。

在主页上，**导出**链接将我们带到下面截图所示的屏幕。除了数据库列表之外，它的结构与其他导出页面相同。

![导出多个数据库](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_06_17.jpg)

### 注意

导出大型数据库可能有效，也可能无效。这取决于它们的大小，所选择的选项，以及 Web 服务器的 PHP 组件设置（特别是内存大小和最大执行时间）。

# 在服务器上保存导出文件

与通过 HTTP 传输导出文件不同，可以直接将其保存在 Web 服务器的文件系统上。这可能会更快，而且不太受执行时间限制的影响，因为从服务器到客户端浏览器的整个传输被绕过了。最终，可以使用文件传输协议（如 FTP 或 SFTP）来检索文件，因为将其留在同一台机器上不会提供良好的备份保护。

在保存导出文件之前，必须在 Web 服务器上创建一个特殊目录。通常，这是主`phpMyAdmin`目录的子目录。我们将使用`save_dir`作为示例。此目录必须具有正确的权限。首先，Web 服务器必须对此目录具有写权限。此外，如果 Web 服务器的 PHP 组件正在安全模式下运行，则 phpMyAdmin 脚本的所有者必须与`save_dir`的所有者相同。

在 Linux 系统上，假设 Web 服务器以`group apache`运行，以下命令可以解决问题：

```sql
# mkdir save_dir
# chgrp apache save_dir
# chmod g=rwx save_dir 

```

### 注意

适当的所有权和权限高度取决于所选择的 Web 服务器和**SAPI（服务器应用程序编程接口）**（参见[`en.wikipedia.org/wiki/Server_Application_Programming_Interface)`](http://en.wikipedia.org/wiki/Server_Application_Programming_Interface))，它影响目录和文件的创建和访问方式。PHP 可能使用脚本所有者作为访问用户，也可能使用 Web 服务器的用户/组本身。

我们还必须在`$cfg['SaveDir']`中定义`'./save_dir'`目录名称。我们在这里使用相对于`phpMyAdmin`目录的路径，但绝对路径同样有效。

**输出**部分将出现一个新的**在服务器上保存..**部分。

![在服务器上保存导出文件](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_06_18.jpg)

点击**Go**后，我们将收到确认消息或错误消息（如果 Web 服务器没有所需的权限来保存文件）。

### 注意

要再次使用相同的文件名保存文件，请勾选**覆盖现有文件**框。

## 用户特定的保存目录

我们可以在`$cfg['SaveDir']`参数中使用特殊字符串`%u`。这个字符串将被登录的用户名替换。例如，如下行代码所示：

```sql
$cfg['SaveDir'] = './save_dir/%u';

```

这将给我们一个屏幕选择，在目录./save_dir/marc/中保存在服务器上。这些目录（每个潜在用户一个）必须存在，并且必须具有适当的权限，如前一节所示。

# 内存限制

生成导出文件会使用一定量的内存，取决于表的大小和选择的选项。`$cfg['MemoryLimit']`参数可以包含 PHP 脚本在 phpMyAdmin 中使用的内存量的限制（以字节为单位）-导出/导入脚本和其他脚本。默认情况下，该参数设置为`0`，表示没有限制。我们可以通过使用`20M`的值来设置 20 MiB 的限制（这里的`M`后缀非常重要，以避免设置 20 字节的限制！）。

### 注意

请注意，如果 PHP 启用了安全模式，更改`$cfg['MemoryLimit']`将不起作用。相反，强制限制来自`php.ini`中的`memory_limit`指令。

除了内存限制，执行时间限制对导出有影响，并且可以通过`$cfg['ExecTimeLimit']`参数进行控制。

# 摘要

在本章中，我们研究了触发导出的各种方式-从`数据库`视图，`表`视图或结果页面。我们还列出了各种可用的导出格式，它们的选项，压缩导出文件的可能性以及可能发送的各种地方。

在下一章中，我们将有机会导入我们的结构和数据，前提是所选的格式得到 phpMyAdmin 支持。


# 第七章：导入结构和数据

在本章中，我们将学习如何导入我们可能为备份或传输目的而导出的数据。导出的数据也可能来自其他应用程序的作者，并且可能包含这些应用程序的整个基础结构以及一些示例数据。

当前的 phpMyAdmin 版本（3.4）可以导入以下内容：

+   包含 MySQL 语句的文件（通常具有`.sql`后缀，但不一定如此）

+   CSV 文件（逗号分隔值，尽管分隔符不一定是逗号）；这些文件可以由 phpMyAdmin 本身导入，也可以通过 MySQL 的`LOAD DATA INFILE`语句导入，该语句使 MySQL 服务器能够直接处理数据，而不是首先由 phpMyAdmin 解析数据

+   打开文档电子表格文件

+   XML 文件（由 phpMyAdmin 生成）

在第五章中涵盖的二进制列上传可以说属于导入系列。

### 注意

在这种情况下，导入和上传是同义词。

一般来说，导出文件可以导入到它来自的同一数据库或任何其他数据库；XML 格式是一个例外，本章后面的 XML 部分中给出了一个解决方法。此外，从旧的 phpMyAdmin 版本生成的文件应该没有问题被当前版本导入，但是导出时的 MySQL 版本与导入时的版本之间的差异可能在兼容性方面起到更大的作用。很难评估未来 MySQL 版本将如何改变语言的语法，带来导入挑战。

可以从几个面板访问导入功能：

+   **导入**菜单可从主页、`Database`视图或`Table`视图中访问

+   **导入文件**菜单在查询窗口内提供（如第十一章中所述）

`Import`界面的默认值在`$cfg['Import']`中定义。

在检查实际导入对话框之前，让我们讨论一些限制问题。

# 传输限制

当我们导入时，源文件通常位于我们的客户端机器上，因此必须通过 HTTP 传输到服务器。这种传输需要时间并使用资源，这些资源可能在 Web 服务器的 PHP 配置中受到限制。

我们可以使用 FTP 等协议将文件上传到服务器，而不是使用 HTTP，如“从 Web 服务器上传目录读取文件”部分所述。这种方法绕过了 Web 服务器的 PHP 上传限制。

## 时间限制

首先，让我们考虑时间限制。在`config.inc.php`中，`$cfg['ExecTimeLimit']`配置指令默认分配了任何 phpMyAdmin 脚本的最大执行时间为 300 秒（五分钟），包括文件上传后处理数据的脚本。值为`0`会移除限制，并在理论上给我们无限的时间来完成导入操作。如果 PHP 服务器运行在安全模式下，修改`$cfg['ExecTimeLimit']`将不会生效。这是因为在`php.ini`或用户相关的 Web 服务器配置文件（如`.htaccess`或虚拟主机配置文件）中设置的限制优先于此参数。

当然，实际花费的时间取决于两个关键因素：

+   Web 服务器负载

+   MySQL 服务器负载

### 注意

文件在客户端和服务器之间传输所花费的时间不计为执行时间，因为 PHP 脚本只有在服务器接收到文件后才开始执行。因此，`$cfg['ExecTimeLimit']`参数只对处理数据的时间（如解压缩或将数据发送到 MySQL 服务器）产生影响。

## 其他限制

系统管理员可以使用`php.ini`文件或 Web 服务器的虚拟主机配置文件来控制服务器上的上传。

`upload_max_filesize`参数指定了可以通过 HTTP 上传的文件的上限或最大文件大小。这个很明显，但另一个不太明显的参数是`post_max_size`。由于 HTTP 上传是通过 POST 方法完成的，这个参数可能会限制我们的传输。有关 POST 方法的更多详细信息，请参考[`en.wikipedia.org/wiki/Http#Request_methods`](http://en.wikipedia.org/wiki/Http#Request_methods)。

`memory_limit`参数用于防止 Web 服务器子进程占用过多服务器内存——phpMyAdmin 在子进程中运行。因此，给这个参数一个较小的值可能会影响正常文件上传的处理，特别是压缩的转储文件。在这里，无法推荐任何首选值；这个值取决于我们想要处理的上传数据的大小和物理内存的大小。内存限制也可以通过`config.inc.php`中的`$cfg['MemoryLimit']`参数进行调整，如第六章所示。

最后，通过将`file_uploads`设置为`On`来允许文件上传；否则，phpMyAdmin 甚至不会显示选择文件的对话框。显示这个对话框是没有意义的，因为后来 Web 服务器的 PHP 组件会拒绝连接。

## 处理大型导出文件

如果文件太大，我们可以通过多种方式解决这个问题。如果原始数据仍然可以通过 phpMyAdmin 访问，我们可以使用 phpMyAdmin 生成较小的导出文件，选择**Dump some row(s)**对话框。如果这不可能，我们可以使用电子表格程序或文本编辑器将文件分割成较小的部分。另一种可能性是使用**上传目录机制**，它访问`$cfg['UploadDir']`中定义的目录。这个功能在本章的后面会有详细解释。

在最近的 phpMyAdmin 版本中，**部分导入**功能也可以解决这个文件大小的问题。通过选择**允许中断...**复选框，如果检测到接近时间限制，导入过程将自行中断。我们还可以指定要从头部跳过的查询数量，以防我们成功导入一些行并希望从那个点继续。

## 上传到临时目录

在服务器上，一个名为`open_basedir`的 PHP 安全功能（将 PHP 可以打开的文件限制为指定的目录树）可能会阻碍上传机制。在这种情况下，或者出于其他任何原因，当上传出现问题时，可以使用`$cfg['TempDir']`参数设置临时目录的值。这可能是 phpMyAdmin 主目录的子目录，Web 服务器允许将上传文件放入其中。

# 导入 SQL 文件

任何包含 MySQL 语句的文件都可以通过这种机制导入。这种格式更常用于备份/恢复目的。对话框可在`服务器`视图、`数据库`视图或`表`视图中，通过**导入**页面或查询窗口中使用。

![导入 SQL 文件](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_07_01.jpg)

### 注意

当前选择的表（这里是**author**）与将要导入的 SQL 文件的实际内容之间没有关系。SQL 文件的所有内容都将被导入，决定受影响的表或数据库的是这些内容。但是，如果导入的文件不包含任何选择数据库的 SQL 语句，那么导入文件中的所有语句都将在当前选择的数据库上执行。

让我们尝试一个导入练习。首先，确保我们有一个`book`表的当前 SQL 导出文件（如第六章中所述）。这个导出文件必须包含结构和数据。然后我们删除`book`表——是的，真的！我们也可以简单地重命名它。（有关该过程，请参阅第九章。）

现在是时候将文件导入到当前数据库中了（文件可以在不同的数据库中进行测试导入，甚至可以在另一个 MySQL 服务器上进行）。我们应该在**导入**页面上，可以看到**要导入的文件**对话框。我们只需要点击**浏览**按钮并选择我们的文件。

phpMyAdmin 能够检测文件应用了哪种压缩方法（如果有的话）。根据 phpMyAdmin 版本和 Web 服务器的 PHP 组件中可用的扩展，程序可以解压缩的格式有所不同。

然而，要成功导入，phpMyAdmin 必须知道要导入的文件的字符集。默认值是**utf-8**。但是，如果我们知道导入文件是用另一种字符集创建的，我们应该在这里指定它。

在导入时，可以选择**SQL 兼容模式**选择器。这种模式应该根据之前导出数据的服务器类型来调整，以匹配我们即将导入的实际数据。

另一个选项**不要对零值使用 AUTO_INCREMENT**默认标记。如果我们在主键中有一个零值，并且希望它保持为零而不是自动递增，我们应该使用这个选项。

要开始导入，我们点击**Go**。导入过程继续，我们收到一条消息：**导入已成功完成，执行了 2 个查询**。我们可以浏览我们新创建的表来确认导入操作的成功。

导入文件可能包含`DELIMITER`关键字。这使得 phpMyAdmin 能够模仿`mysql`命令行解释器。`DELIMITER`分隔符用于界定包含存储过程的文件部分，因为这些过程本身可能包含分号。

# 导入 CSV 文件

在本节中，我们将研究如何导入 CSV 文件。有两种可能的方法——**CSV**和**使用 LOAD DATA 的 CSV**。第一种方法是由 phpMyAdmin 内部实现的，因为它的简单性而被推荐。使用第二种方法，phpMyAdmin 接收要加载的文件，并将其传递给 MySQL。理论上，这种方法应该更快。然而，由于 MySQL 本身的要求更多（请参阅*CSV 使用 LOAD DATA*部分的*要求*子部分）。

## SQL 和 CSV 格式之间的区别

通常，SQL 格式包含结构和数据。CSV 文件格式只包含数据，因此如果我们在`表`视图中导入，我们必须已经有一个现有的表。这个表不需要与原始表（数据来自哪里）具有相同的结构；**列名**对话框使我们能够选择目标表中受影响的列。

自 3.4 版本以来，我们还可以在`数据库`视图中导入 CSV 文件。在这种情况下，phpMyAdmin 会检查 CSV 数据并生成一个表结构来保存这些数据（具有通用列名，如`COL 1，COL 2`和一个表名，如`TABLE 24`）。

## 导出测试文件

在尝试导入之前，让我们从`author`表中生成一个`author.csv`导出文件。我们使用**CSV 导出**选项中的默认值。然后我们可以使用**Empty**选项来清空`author`表——我们应该避免删除这个表，因为我们仍然需要表结构。清空表的过程在第五章中有介绍，在*删除表中的所有行*部分。

### CSV

从`author`表菜单中，我们选择**导入**，然后选择**CSV**。

![CSV](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_07_02.jpg)

我们可以通过多种方式影响导入的行为。默认情况下，导入不会修改现有数据（基于主键或唯一键）。然而，“用文件替换表数据”选项指示 phpMyAdmin 使用 REPLACE 语句而不是 INSERT 语句，以便用导入的数据替换现有行。

使用“在 INSERT 错误时不中止”，将生成 INSERT IGNORE 语句。这会导致 MySQL 在插入时忽略任何重复键的问题。导入文件中的重复键不会替换现有数据，程序会继续下一行 CSV 数据。

然后我们可以指定终止每一列的字符，包围数据的字符，以及转义包围字符的字符。通常是“\”。

对于“行终止符”选项，应首先尝试“auto”选项，因为它会自动检测行尾字符。我们还可以手动指定终止行的字符。通常 UNIX 系统选择“\n”，DOS 或 Windows 系统选择“\r\n”，Mac 系统选择“\r”（Mac OS 9 及以下）。如果不确定，我们可以在客户端计算机上使用十六进制文件编辑器（不是 phpMyAdmin 的一部分）来检查确切的代码。

默认情况下，phpMyAdmin 期望 CSV 文件与目标表具有相同数量的列和相同的列顺序。这可以通过在“列名”中输入一个逗号分隔的列名列表来改变，以符合源文件格式。例如，假设我们的源文件只包含作者 ID 和作者姓名信息：

```sql
"1","John Smith"
"2","Maria Sunshine"

```

我们必须在“列名”中放入“id，name”以匹配源文件。

当我们点击“Go”时，导入将被执行，并且我们会收到确认。如果文件的总大小不太大，我们还可能看到生成的 INSERT 查询。

```sql
Import has been successfully finished, 2 queries executed.
INSERT INTO `author` VALUES ('1', 'John Smith', '+01 445 789-1234'
)# 1 row(s) affected.
INSERT INTO `author` VALUES ('2', 'Maria Sunshine', '333-3333'
)# 1 row(s) affected.

```

## 使用 LOAD DATA 的 CSV

使用这种方法（仅在“表”视图中可用），phpMyAdmin 依赖服务器的 LOAD DATA INFILE 或 LOAD DATA LOCAL INFILE 机制来执行实际的导入，而不是在内部处理数据。这些语句是在 MySQL 中导入文本的最快方式。它们会导致 MySQL 开始从 MySQL 服务器上的文件（LOAD DATA INFILE）或其他地方（LOAD DATA LOCAL INFILE）进行读取操作，而在这种情况下，通常是 Web 服务器的文件系统。如果 MySQL 服务器位于与 Web 服务器不同的计算机上，我们将无法使用 LOAD DATA INFILE 机制。

### 要求

依赖 MySQL 服务器会产生一些后果。使用 LOAD DATA INFILE 要求登录用户拥有全局的 FILE 权限。此外，文件本身必须可被 MySQL 服务器的进程读取。

### 注意

第十九章解释了 phpMyAdmin 的界面，系统管理员可以使用该界面来管理权限。

在 PHP 中使用 LOAD DATA LOCAL INFILE 时，必须允许 MySQL 服务器和 MySQL 的客户端库中的 LOCAL 修饰符。

phpMyAdmin 的 LOAD 界面提供了两种 LOAD 方法，试图选择最佳的默认选项。

### 使用 LOAD DATA 界面

我们从`author`表菜单中选择导入。选择 CSV using LOAD DATA 选项会弹出以下对话框：

![使用 LOAD DATA 界面](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_07_03.jpg)

### 注意

可用的选项已经在 CSV 部分中介绍过了。

在“要导入的文件”部分，我们选择我们的 author.csv 文件。

最后，我们可以选择 LOAD 方法，如前面讨论的，通过选择“使用 LOCAL 关键字”选项。然后点击“Go”。

如果一切顺利，我们可以看到确认屏幕，如下截图所示：

![使用 LOAD DATA 界面](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_07_04.jpg)

这个屏幕显示了使用的 LOAD DATA LOCAL INFILE 语句。以下是发生的事情：

1.  我们选择了 author.csv。

1.  这个文件的内容通过 HTTP 传输并被 Web 服务器接收。

1.  Web 服务器内的 PHP 组件将此文件保存在工作目录（此处为`/opt/php-upload-tmp/`）并赋予临时名称。

1.  phpMyAdmin 知道这个工作文件的位置后，构建了一个`LOAD DATA LOCAL INFILE`命令，并将其发送到 MySQL。请注意，只执行了一个查询，加载了许多行。

1.  MySQL 服务器读取并加载了文件的内容到我们的目标表中。然后返回受影响的行数**(2)**，phpMyAdmin 在结果页面上显示了这个数字。

# 导入其他格式

除了 SQL 和 CSV 格式，phpMyAdmin 还可以导入 Open Document Spreadsheet 和 XML 文件。但是，这些文件需要由 phpMyAdmin 自己导出，或者紧密遵循 phpMyAdmin 导出时的操作。

## Open Document Spreadsheet

默认情况下，当我们以这种格式通过 phpMyAdmin 导出时，**将列名放在第一行**选项未被标记。这意味着导出的文件只包含数据。在导入时，相应的选项**文件的第一行包含表列名**被提供，并且如果文件的第一行不包含列名，则不应该被标记。

但是，如果导出的文件包含列名，我们可以检查这个选项。因此，当从`数据库`视图导入时，phpMyAdmin 将执行以下操作：

1.  使用文件名`(author.ods)`作为表名`(author)`创建表。

1.  使用第一行的列名作为此表的列名。

1.  根据数据本身确定每个列的类型和适当的大小。

1.  将数据插入表中。

如果我们处于`表`视图中，只有数据将被导入。

还有其他导入选项，用于指示应该如何处理空行以及包含百分比或货币值的数据。

## XML

通过导入 XML 文件创建的结构信息的数量取决于导出时选择的选项。实际上，如果选择了**对象创建选项**对话框的**表**选项，那么精确的`CREATE TABLE`语句将被放置在导出文件中。因此，恢复表中将有相同的表结构。

同样，如果标记了**导出内容**选项，则整个数据都在 XML 文件中准备好导入。在导入时没有可用选项，因为 XML 是一种自描述格式；因此，phpMyAdmin 可以正确解释文件中的内容并做出适当的反应。

由于原始数据库名称是 XML 导出的一部分，当前的 phpMyAdmin 版本只支持将 XML 文件导入到导出源数据库中。要导入到不同的数据库，我们需要首先使用文本编辑器并更改以下行中的数据库名称：

```sql
<pma:database name="marc_book" collation="latin1_swedish_ci" charset="latin1">

```

# 从 Web 服务器上传目录读取文件

为了解决 Web 服务器的 PHP 配置完全禁用上传的情况，或者上传限制太小的情况，phpMyAdmin 可以从 Web 服务器文件系统上的特殊目录中读取上传文件。

首先，在`$cfg['UploadDir']`参数中指定我们选择的目录名称，例如，`'./upload'`。我们还可以使用`%u`字符串，如第六章中所述，来表示用户的名称。

现在，让我们回到**导入**页面。我们收到一个错误消息：

**您设置的上传工作目录无法访问**。

这个错误消息是预期的，因为该目录不存在。它应该已经在当前的`phpMyAdmin`安装目录内创建。该消息也可能表明该目录存在，但无法被 Web 服务器读取。

### 注意

在 PHP 安全模式下，目录的所有者和 phpMyAdmin 安装脚本的所有者必须相同。

使用 SFTP 或 FTP 客户端，我们创建必要的目录，现在可以在那里上传文件（例如**book.sql**），绕过任何 PHP 超时或上传最大限制。

### 提示

请注意，文件本身必须具有允许 Web 服务器读取的权限。

在大多数情况下，最简单的方法是允许每个人都可以读取文件。

刷新**导入**页面会出现以下截图：

从 Web 服务器上传目录读取文件的操作如下图所示：

点击**Go**应该执行文件中的语句。

上传目录中的文件也可以自动解压缩。文件名应该具有`.bz2, .gz, .sql.bz2`或`.sql.gz`等扩展名。

### 提示

使用双扩展名`(.sql.bz2)`是指示`.sql`文件已经生成并压缩的更好方式，因为我们看到了生成此文件所使用的所有步骤。

# 显示上传进度条

特别是在导入大文件时，有一个视觉反馈对上传进度的进行是很有趣的。请注意，我们在这里讨论的进度条只通知我们有关上传部分的进度，这是整个导入操作的一个子集。

拥有启用 JavaScript 的浏览器是此功能的要求。此外，Web 服务器的 PHP 组件必须具有 JSON 扩展和以下扩展中的至少一个：

+   广为人知的 APC 扩展（[`pecl.php.net/package/APC`](http://pecl.php.net/package/APC)），无论如何都强烈推荐它的 opcode 缓存优势

+   `uploadprogress`扩展（[`pecl.php.net/package/uploadprogress`](http://pecl.php.net/package/uploadprogress)）

phpMyAdmin 使用 AJAX 技术获取进度信息，然后将其显示为**要导入的文件**对话框的一部分。上传的字节数、总字节数和上传百分比显示在条形图下方。

## 配置 APC

一些`php.ini`指令对上传进度起着重要作用。首先，`apc.rfc1867`指令必须设置为`On`或`true`，否则该扩展将不会向调用脚本报告上传进度。当设置为`On`时，该扩展会使用上传状态信息更新 APC 用户缓存条目。

此外，更新的频率可以通过`apc.rfc1867_freq`指令进行设置，可以采用总文件大小的百分比形式（例如，`apc.rfc1867_freq = "10%"`），或以字节为单位的大小（接受后缀`k`表示千字节，`m`表示兆字节，`g`表示千兆字节）。这里的值为`0`表示尽可能频繁地更新，看起来很有趣，但实际上可能会减慢上传速度。

更新频率的概念解释了为什么在使用这种机制时，进度条以块状而不是连续地进行。

# 总结

本章涵盖了：

+   phpMyAdmin 中允许我们导入数据的各种选项

+   导入文件涉及的不同机制

+   尝试传输时可能遇到的限制，以及绕过这些限制的方法

下一章将解释如何进行单表搜索（涵盖搜索条件规范）以及如何在整个数据库中进行搜索。


# 第八章：搜索数据

在本章中，我们介绍了可用于查找我们正在寻找的数据的机制，而不仅仅是浏览表格页面并对其进行排序。在**搜索**模式下，应用程序开发人员可以以界面不期望的方式查找数据，调整并有时修复数据。本章涵盖了单表搜索和整个数据库搜索。第十二章是本章的补充，并提供了涉及同时多个表的搜索示例。

# 单表搜索

本节描述了**搜索**页面，其中提供了单表搜索。仅在单个表中搜索仅在单个表中聚合了我们想要搜索的所有数据的情况下才有效。如果数据分散在许多表中，则应该启动数据库搜索，这将在本章后面进行介绍。

## 输入搜索页面

可以通过在`Table`视图中点击**搜索**链接来访问**搜索**页面。这在这里已经为`book`表完成了：

![输入搜索页面](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_08_01.jpg)

**搜索**界面最常用的部分**（示例查询）**会立即显示，而其他对话框则隐藏在可以通过**选项**链接激活的滑块中（本章后面将更多介绍这些对话框）。

## 按列搜索条件-示例查询

**搜索**面板的主要用途是输入某些列的条件，以便只检索我们感兴趣的数据。这被称为**示例查询**，因为我们给出了我们要查找的内容的示例。我们的第一个检索将涉及查找具有 ISBN **1-234567-89-0**的书。我们只需在**isbn**框中输入这个值，并将**运算符**字段设置为**=**。

![按列搜索条件-示例查询](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_08_02.jpg)

点击**Go**会给出以下结果（在下面的截图中部分显示）：

![按列搜索条件-示例查询](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_08_03.jpg)

这是一个标准的结果页面。如果结果分页显示，我们可以浏览它们，并在过程中编辑和删除所选择的子集的数据。phpMyAdmin 的另一个特性是，用作条件的列通过更改边框颜色来突出显示，以更好地反映它们在结果页面上的重要性。

并不需要指定**isbn**列被显示，即使这是我们搜索的列。我们可以仅选择**title**列进行显示（参考*选择要显示的列*部分），并选择**isbn**列作为条件。

### 搜索空/非空值

当列具有字符类型（如`CHAR，VARCHAR`或`TEXT`）时，操作符列表中会出现两个方便的操作符：

+   `= ''`

+   `!= ''`

当您想要搜索某列中的空值`(= '')`或非空值`(!= '')`时，可以使用这些。通常，在列的**值**字段中不输入任何内容意味着该列不参与搜索过程。但是，使用这些运算符之一，该列将包括在生成的搜索查询中。

### 注意

请不要将此方法与搜索`NULL`值混淆，这是完全不同的。实际上，`NULL`值（参考[`en.wikipedia.org/wiki/Null_(SQL)`](http://en.wikipedia.org/wiki/Null_(SQL) "http://en.wikipedia.org/wiki/Null_(SQL)")以获取更完整的解释）是一种特殊值，表示该列中缺少一些信息。

## 使用打印视图生成报告

我们在结果页面上看到了**打印视图**和**打印视图（带有完整文本）**链接。这些链接会直接将结果（不包括导航界面）更正式地生成报告并直接发送到打印机。在我们的情况下，使用**打印视图**会产生以下结果：

![使用打印视图生成报告](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_08_04.jpg)

这份报告包含有关服务器、数据库、生成时间、phpMyAdmin 版本、MySQL 版本和生成的 SQL 查询的信息。另一个链接**打印视图（带有完整文本）**将打印`TEXT`列的全部内容。

## 使用通配符字符进行搜索

让我们假设我们正在寻找一些不太精确的东西——所有标题中带有“电影”一词的书籍。首先，我们回到搜索页面。对于这种类型的搜索，我们将使用 SQL 的**LIKE**运算符。该运算符接受通配符字符——百分号（`%`）字符（匹配任意数量的字符）和下划线（`_`）字符（匹配单个字符）。因此，我们可以使用**%cinema%**让 phpMyAdmin 找到任何与单词“cinema”匹配的子字符串。如果我们省略了通配符字符，我们将只得到包含该单词的精确匹配。

这种子字符串匹配更容易访问，因为它是**运算符**下拉列表的一部分。我们只需输入单词**cinema**并使用运算符**LIKE %...%**进行匹配。我们应该避免在大表上使用这种形式的**LIKE**运算符（包含数千行），因为 MySQL 在这种情况下不会使用索引进行数据检索，导致等待时间取决于服务器硬件及其当前负载。这就是为什么这个运算符不是下拉列表中的默认选项，即使这种搜索方法在较小的表上通常被使用。

以下屏幕截图显示了我们如何使用**LIKE %...%**运算符要求搜索**cinema**：

![使用通配符字符进行搜索](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_08_05.jpg)

### 注意

`LIKE`运算符可以用于其他类型的通配符搜索，例如`History%`，这将在标题开头搜索这个词。由于表达式不以通配符字符开头，MySQL 将尝试使用索引来加快数据检索。有关 MySQL 索引的更多详细信息，请参阅[`dev.mysql.com/doc/refman/5.1/en/mysql-indexes.html`](http://dev.mysql.com/doc/refman/5.1/en/mysql-indexes.html)。

使用这两种查询方法之一会产生以下结果：

![使用通配符字符进行搜索](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_08_06.jpg)

在搜索表达式中可以重复使用`%`和`_`通配符字符；例如，`histo__`（两个下划线）将匹配`history`，而`histo%`将匹配`history`和`historian`。MySQL 手册在[`dev.mysql.com/doc/refman/5.1/en/string-comparison-functions.html`](http://dev.mysql.com/doc/refman/5.1/en/string-comparison-functions.html)中给出了更多示例。

## 大小写敏感和搜索

在前面的例子中，我们可以用“CINEMA”替换“cinema”并获得类似的结果。原因是**title**列的排序规则是**latin1_swedish_ci**。这种排序规则来自于在数据库创建时默认设置的排序规则集，除非服务器的默认排序规则已更改（参见[`dev.mysql.com/doc/refman/5.1/en/charset-mysql.html)`](http://dev.mysql.com/doc/refman/5.1/en/charset-mysql.html)）。这里，**ci**表示比较是以不区分大小写的方式进行的。有关更多详细信息，请参阅[`dev.mysql.com/doc/refman/5.1/en/case-sensitivity.html`](http://dev.mysql.com/doc/refman/5.1/en/case-sensitivity.html)。

## 组合条件

我们可以为同一查询使用多个条件（例如，查找所有超过 300 页的英文书籍）。在**运算符**中有更多比较选择，因为**page_count**列是数字型的，如下面的屏幕截图所示：

![组合条件](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_08_07.jpg)

## 搜索选项

**选项**滑块显示了额外的面板，以进一步细化搜索过程。

### 选择要显示的列

在“选项”滑块中，“选择列”面板方便地选择要在结果中显示的列。默认情况下会选择所有列，但我们可以使用“Ctrl”+单击其他列来进行必要的选择。Mac 用户将使用“Command”+单击来选择/取消选择列。

以下是此示例中感兴趣的列：

![选择要显示的列](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_08_08.jpg)

我们还可以在列选择旁边的文本框中指定每页的行数。稍后将在“应用 WHERE 子句”部分中解释“添加搜索条件”框。

### 排序结果

“显示顺序”对话框允许指定结果的初始排序顺序。在此对话框中，下拉菜单包含所有表的列；我们可以选择要排序的列。默认情况下，排序将按升序进行，但也可以选择降序。

值得注意的是，在结果页面上，我们可以使用第四章中解释的技术来更改排序顺序。

### 应用 WHERE 子句

有时，我们可能希望输入一个在“示例查询”部分的“函数”列表中没有提供的搜索条件。该列表无法包含语言中的每种可能的变化。假设我们想要使用`IN`子句找到所有英语或法语的书。为此，我们可以使用“添加搜索条件”部分。

![应用 WHERE 子句](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_08_09.jpg)

### 注意

通过将搜索条件和其他条件（在“示例查询”行中输入）与逻辑`AND`运算符组合生成完整的搜索表达式。

我们可以有一个更复杂的搜索条件列表，可以在同一个文本框中输入，可能包括括号和`AND`或`OR`等运算符。

“文档”链接指向 MySQL 手册，我们可以在那里看到大量可用函数的选择。（每个函数适用于特定的列类型。）

### 避免重复结果

`SELECT`语句的正常行为是获取与条件相对应的所有条目，即使有些条目重复。有时，我们可能希望避免多次获取相同的结果。例如，如果我们想知道我们在哪些城市有客户，只显示每个城市的名称一次就足够了。在这里，我们想知道我们的书是用哪种语言写的。在“选择列”对话框中，我们只选择“语言”列，并勾选“DISTINCT”，如下面的屏幕截图所示：

![避免重复结果](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_08_10.jpg)

单击“Go”会生成一个结果页面，在那里我们只看到“en”一次；如果没有“DISTINCT”选项，包含“en”的行将出现三次。

如果我们选择了多个列（例如`author_id`和`language`）并标记了`DISTINCT`选项，那么现在我们将在结果中看到两行，因为有两本书是用英语写的（但来自不同的作者）。结果仍然不重复。

# 执行完整的数据库搜索

在前面的示例中，搜索被限制在一个表中。这假设我们知道可能存储所需信息的确切表（和列）。

当数据隐藏在数据库中的某个地方，或者当相同的数据可以以各种列的形式呈现（例如，“标题”列或“描述”列），使用数据库搜索方法会更容易。

我们在`marc_book`数据库的“数据库”视图中进入“搜索”页面：

![执行完整的数据库搜索](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_08_11.jpg)

在“单词或值”部分，我们输入想要查找的内容。在这里，“%”通配符字符可能会很有用，但请记住本章前面提到的通配符字符的性能建议。我们输入“纪念品”。

在**Find**部分，我们指定如何处理输入的值。我们可能需要找到**至少一个输入的单词**，**所有单词**（无特定顺序），或**确切的短语**（单词按相同顺序出现在某个列中）。另一个选择是使用**作为正则表达式**，这是一种更复杂的模式匹配方式。更多细节可在[`dev.mysql.com/doc/refman/5.1/en/regexp.html`](http://dev.mysql.com/doc/refman/5.1/en/regexp.html)和[`www.regular-expressions.info/`](http://www.regular-expressions.info/)找到。我们将保持默认值——**至少一个输入的单词**。

我们可以选择要限制搜索的表，或选择所有表。由于我们只有两个（小）表，我们选择了两个。

### 注意

由于搜索将在所选表的每一行上进行，如果行数或表的数量太大，我们可能会遇到一些时间限制。因此，可以通过将`$cfg['UseDbSearch']`设置为`FALSE`来停用此功能（默认设置为`TRUE`）。

点击**Go**为我们找到以下结果：

![执行完整的数据库搜索](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_08_12.jpg)

这是匹配数量和相关表的概述。我们可能会在我们不感兴趣的表中找到一些匹配。但是，对于看起来有希望的匹配，我们可以点击**browse**来浏览结果页面，或者我们可以选择**delete**来删除不需要的行。**show search criteria**链接将带回我们的条件面板。

## 限制搜索到一列

有时，特定的列名是一个（或多个）表的一部分，我们只想在这个列中进行搜索。例如，假设我们正在寻找"marc"；但这个名字也可能是书名的一部分。因此，我们只想在所有选择的表的"name"列中限制搜索。这可以通过在**inside column**选项中输入"name"来实现。

# 停止错误的查询

假设我们启动了一个复杂的搜索，并注意到浏览器正在等待结果。这可能发生在数据库搜索中，也可能发生在单表搜索中。我们可以指示浏览器停止，但这只会告诉 Web 服务器停止处理我们的请求。然而，此时 MySQL 服务器进程正在忙碌，可能正在进行复杂的连接或完整的表扫描。以下是停止这个错误查询的方法：

1.  我们打开一个不同的浏览器（例如，错误的查询是通过 Firefox 启动的，我们打开 Internet Explorer）。

1.  我们使用相同的帐户通过 phpMyAdmin 登录到 MySQL。

1.  在主页上，我们点击**Processes**。

1.  此时，我们应该在**Command**列下看到一个由**Query**标识的进程，并包含错误的查询（而不是`SHOW PROCESSLIST`，这不是要终止的进程）。

1.  我们点击**Kill**来终止这个进程。

1.  为了验证，我们可以立即再次点击**Processes**，选择的进程现在应该被标识为**Killed**而不是**Query**。

# 摘要

在本章中，我们概述了带有“按示例查询”的单表搜索以及附加条件规范的概述——选择显示的值和排序结果。我们还研究了通配符搜索和完整的数据库搜索。

下一章将解释如何对表执行操作，例如更改表的属性，比如存储引擎。本章还涵盖了修复和优化表的主题。


# 第九章：执行表和数据库操作

在前几章中，我们主要处理了表列。在本章中，我们将学习如何执行一些影响整个表或数据库的操作。我们将涵盖表属性以及如何修改它们，并讨论多表操作。

在`表`视图的**操作**页面上汇集了各种启用表操作的链接。以下是此页面的概述：

![执行表和数据库操作](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_09_01.jpg)

# 维护表

在其生命周期中，表会反复修改，因此不断增长和缩小。服务器可能会出现中断，导致一些表处于损坏状态。

使用**操作**页面，我们可以执行各种操作，下面列出了这些操作。但是，并非每种存储引擎都支持每种操作。

+   **检查表：**扫描所有行以验证删除的链接是否正确。还会计算校验和以验证键的完整性。如果一切正常，我们将获得一个显示**OK**或**表已经是最新的**的消息；如果出现其他消息，现在是修复此表的时候了（参考**修复表**项目）。

+   **分析表：**分析并存储键分布；这将在后续的`JOIN`操作中用于确定应该连接表的顺序。应定期执行此操作（如果表中的数据已更改）以提高`JOIN`效率。

+   **修复表：**修复`MyISAM`和`ARCHIVE`引擎中表的任何损坏数据。请注意，表可能会损坏到我们甚至无法进入`表`视图！在这种情况下，请参考*多表操作*部分以修复它的程序。

+   **碎片整理表：**在`InnoDB`表中进行随机插入或删除会使其索引碎片化。应定期对表进行碎片整理以加快数据检索。此操作会导致 MySQL 重建表，并且仅适用于`InnoDB`。

+   **优化表：**当表包含开销时，这是有用的。在大量删除行或`VARCHAR`列长度更改后，表中会保留丢失的字节。如果 phpMyAdmin 在各个地方（例如在`结构`视图中）感觉表应该被优化，它会警告我们。此操作将回收表中未使用的空间。在 MySQL 5.x 的情况下，可以优化的相关表使用`MyISAM，InnoDB`和`ARCHIVE`引擎。

+   **刷新表：**当出现许多连接错误并且 MySQL 服务器阻止进一步连接时，必须执行此操作。刷新将清除一些内部缓存，并允许正常操作恢复。

### 注意

操作是基于可用的底层 MySQL 查询进行的 - phpMyAdmin 只调用这些查询。更多详细信息请参阅[`dev.mysql.com/doc/refman/5.5/en/table-maintenance-sql.html`](http://dev.mysql.com/doc/refman/5.5/en/table-maintenance-sql.html)。

# 更改表属性

表属性是表的各种属性。本节讨论了其中一些设置的设置。

## 表存储引擎

我们可以更改的第一个属性称为**存储引擎**。

![表存储引擎](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_09_02.jpg)

这控制了表的整体行为 - 其位置（在磁盘上或内存中）、索引结构以及是否支持事务和外键。下拉列表取决于我们的 MySQL 服务器支持的存储引擎。

### 注意

如果行数较多，更改表的存储引擎可能是一个长时间的操作。

## 表注释

**表注释**选项允许我们为表输入注释。

![表注释](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_09_03.jpg)

这些注释将显示在适当的位置，例如在导航面板中，在`Table`视图中的表名称旁边，以及在导出文件中。以下屏幕截图显示了当`$cfg['ShowTooltip']`参数设置为其默认值`TRUE`时导航面板的外观：

![表注释](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_09_04.jpg)

`$cfg['ShowTooltipAliasDB']`和`$cfg['ShowTooltipAliasTB']`的默认值为`(FALSE)`，会产生我们之前看到的行为—导航面板和`Structure`页面中显示真实的数据库和表名。当光标悬停在数据库或表名上时，注释会显示为工具提示。如果其中一个参数设置为`TRUE`，则行为将反转—默认显示注释，并将真实名称显示为工具提示。当真实表名不具有意义时，这是方便的。

还有另一种可能性是`$cfg['ShowTooltipAliasTB']`的值为`'nested'`。如果使用此功能会发生什么：

+   导航面板中显示真实表名

+   表注释（例如，`project__`）被解释为项目名称，并按原样显示（参见第三章中的*数据库中表的嵌套显示*部分）

## 表顺序

当我们浏览表，或执行诸如`SELECT * from book`之类的语句而没有指定排序顺序时，MySQL 使用行物理存储的顺序。可以使用**Alter table order by**对话框更改表顺序。我们可以选择任何列，表将在此列上重新排序一次。在示例中，我们选择**author_id**，然后单击**Go**，表将按此列排序。

如果我们知道大部分时间将按此顺序检索行，则重新排序是方便的。此外，如果以后使用`ORDER BY`子句，并且表已经在此列上物理排序，可能会获得更好的性能。

默认排序将持续到表中没有更改（没有插入、删除或更新）为止。这就是为什么 phpMyAdmin 显示**(单独)**警告。

![表顺序](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_09_05.jpg)

在对**author_id**进行排序后，作者**1**的书将首先显示，然后是作者**2**的书，依此类推（我们谈论的是默认浏览表而没有明确排序）。我们还可以指定排序顺序为**升序**或**降序**。

如果我们插入另一行，描述来自作者**1**的新书，然后单击**浏览**，由于排序是在插入之前完成的，该书将不会与此作者的其他书一起显示。

## 表排序规则

基于字符的列具有描述用于解释内容的字符集以及排序规则的排序属性。**name**列当前具有**latin1_swedish_ci**排序规则，可以通过**Structure**页面看到。在**Operations**页面上，如果我们将表`author`的排序规则从**latin1_swedish_ci**更改为**utf8_general_ci**，则会生成以下语句：

```sql
ALTER TABLE `author` DEFAULT CHARACTER SET utf8 COLLATE utf8_general_ci

```

因此，我们只更改了将来将添加到此表中的列的默认排序规则；对于现有列，未更改排序规则。

## 表选项

可以使用**表选项**对话框指定影响表行为的其他属性：

![表选项](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_09_06.jpg)

选项包括：

+   **PACK_KEYS：**设置此属性会导致较小的索引。这样可以更快地读取，但更新需要更多时间。适用于`MyISAM`存储引擎。

+   **CHECKSUM：**这使得 MySQL 为每一行计算一个校验和。这会导致更新速度变慢，但查找损坏的表变得更容易。仅适用于`MyISAM`。

+   **DELAY_KEY_WRITE：**这指示 MySQL 不立即写入索引更新，而是将它们排队以便稍后写入。这可以提高性能，但存在负面折衷——在服务器故障的情况下可能需要重建索引（参见[`dev.mysql.com/doc/refman/5.1/en/miscellaneous-optimization-tips.html)`](http://dev.mysql.com/doc/refman/5.1/en/miscellaneous-optimization-tips.html)）。仅适用于`MyISAM`。

+   **TRANSACTIONAL、PAGE_CHECKSUM：**适用于`Aria`存储引擎，以前称为`Maria`。**TRANSACTIONAL**选项将此表标记为事务性表；然而，此选项的确切含义会随着此存储引擎的未来版本获得更多的事务性功能而变化。**PAGE_CHECKSUM**计算所有索引页的校验和。目前在[`kb.askmonty.org/en/aria-storage-engine`](http://kb.askmonty.org/en/aria-storage-engine)中有文档记录。

+   **ROW_FORMAT：**对支持此功能的存储引擎（`MyISAM、InnoDB、PBXT`和`Aria`）提供了一种行格式的选择。默认值是该表行格式的当前状态。

+   **AUTO_INCREMENT：**这会更改自动递增值。仅当表的主键具有自动递增属性时才显示。

# 清空或删除表

清空表（删除其数据）和删除表（删除其数据和表的结构）可以通过**清空表（TRUNCATE）**和**删除表（DROP）**链接来完成，这些链接位于**删除数据或表**部分。

# 重命名、移动和复制表

**重命名**操作是最容易理解的——表只是更改其名称并保持在同一数据库中。

**移动**操作（如下截图所示）以两种方式操作表——更改其名称以及存储它的数据库。

![重命名、移动和复制表](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_09_07.jpg)

MySQL 不直接支持移动表。因此，phpMyAdmin 必须在目标数据库中创建表，复制数据，然后最终删除源表。这可能需要很长时间，具体取决于表的大小。

**复制**操作会保留原始表并将其结构或数据（或两者）复制到另一个表中，可能是另一个数据库中。在这里，**book-copy**表将是`book`源表的精确副本。复制后，我们仍然保持在`book`表的`Table`视图中，除非我们选择了**切换到复制表**选项，此时我们将移动到新创建表的`Table`视图中。

![重命名、移动和复制表](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_09_08.jpg)

**仅结构**复制用于创建具有相同结构但没有数据的测试表。

## 向表追加数据

复制对话框也可以用于将数据从一个表追加（添加）到另一个表中。两个表必须具有相同的结构。通过输入我们想要复制数据的表并选择**仅数据**来实现此操作。

例如，图书数据来自各种来源（各种出版商）以每个出版商一个表的形式，并且我们希望将所有数据汇总到一个地方。对于`MyISAM`，可以通过使用`Merge`存储引擎（这是一组相同的`MyISAM`表）来获得类似的结果。但是，如果表是`InnoDB`，我们需要依赖 phpMyAdmin 的**复制**功能。

# 执行其他表操作

在**操作**界面上，可能会出现其他对话框。引用完整性验证对话框将在第十章中介绍。分区维护将在第十七章中进行检查。

# 多表操作

在`数据库`视图中，每个表名旁边都有一个复选框，并且在表列表下方有一个下拉菜单。这使我们能够快速选择一些表并一次对所有这些表执行操作。在这里，我们选择**book-copy**和**book**表，并选择所选表的**检查表**操作，如下截图所示：

![多表操作](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_09_09.jpg)

我们还可以使用**全选/取消全选**选项快速选择或取消选择所有复选框。

## 修复“正在使用”的表

多表模式是修复损坏表的唯一方法（除非我们知道要输入的确切 SQL 查询）。此类表可能在数据库列表中显示为**正在使用**标志。在 phpMyAdmin 的支持论坛中寻求帮助的用户经常会从经验丰富的 phpMyAdmin 用户那里得到这个提示。

# 数据库操作

`数据库`视图中的**操作**选项卡提供了访问面板的权限，使我们能够对整个数据库执行操作，如下截图所示：

![数据库操作](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_09_10.jpg)

## 重命名数据库

**重命名数据库为**对话框可用。虽然 MySQL 不直接支持此操作，但 phpMyAdmin 通过创建新数据库，重命名每个表（从而将其发送到新数据库）并删除原始数据库来间接执行此操作。

## 复制数据库

即使 MySQL 本身不原生支持此操作，也可以对数据库进行完整复制。选项与已经解释的表复制类似。

![复制数据库](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_09_11.jpg)

# 摘要

本章介绍了我们可以对整个表或数据库执行的操作。还介绍了表维护操作，包括表修复和优化，更改各种表属性，表移动（包括重命名和移动到另一个数据库）和多表操作。

在下一章中，我们将开始研究依赖于 phpMyAdmin 配置存储的高级功能，例如关系系统。


# 第十章：从关系系统中受益

关系系统允许用户更密切地与 phpMyAdmin 合作，我们将在接下来的章节中看到。本章将解释如何定义表格之间的关系。

# 关系型 MySQL

当应用程序开发人员使用 PHP 和 MySQL 构建 Web 界面或其他数据操作应用程序时，他们通常使用底层 SQL 查询来建立表格之间的关系。例如，"获取发票及其所有项目"和"获取作者的所有书籍"等查询。

在早期版本的 phpMyAdmin 中，关系数据结构（表格之间的关系）并未存储在 MySQL 中。表格是通过应用程序进行程序化连接以生成有意义的结果的。

这被 phpMyAdmin 开发人员和用户认为是 MySQL 的一个缺点。因此，团队开始构建基础设施，以支持`MyISAM`表的关系，现在称为 phpMyAdmin 配置存储。这个基础设施发展到支持越来越多的特殊功能，如查询书签和基于 MIME 的转换。

现在，表格之间的关系通常是使用`InnoDB`和`PBXT`存储引擎的`FOREIGN KEY`功能本地定义的。phpMyAdmin 支持这种类型的关系以及为`MyISAM`定义的关系。

## InnoDB 和 PBXT

`InnoDB`（[`www.innodb.com`](http://www.innodb.com)）是由 Innobase Oy，Oracle 的子公司开发的 MySQL 存储引擎。在 MySQL 5.5 之前，这个存储引擎可能不可用，因为它必须由系统管理员激活；然而，在 5.5 版本中，它是默认的存储引擎。

`PrimeBase XT`存储引擎或 PBXT（[`www.primebase.org`](http://www.primebase.org)）是由 PrimeBase Technologies 开发的。最低要求的 MySQL 版本是 5.1，因为这个版本支持可插拔存储引擎 API，这个 API 被`PBXT`和其他第三方用来提供替代存储引擎。这个事务性存储引擎比`InnoDB`更新。通常在从他们的网站下载后进行编译步骤后安装。对于一些操作系统，也有预编译的二进制文件可用-请访问上述网站获取下载和安装说明。

在考虑关系方面，对于表格使用`InnoDB`或`PBXT`存储引擎的好处有：

它们支持基于外键的引用完整性，这些外键是外部（或引用）表中的键。相比之下，仅使用 phpMyAdmin 的内部关系（稍后讨论）不会带来自动的引用完整性验证。

`InnoDB`和`PBXT`表的导出结构包含了定义的关系。因此，它们可以轻松地被重新导入，以实现更好的跨服务器互操作性。

这些存储引擎的外键功能可以有效地替代 phpMyAdmin 配置存储中处理关系的部分。我们将看到 phpMyAdmin 如何与`InnoDB`和`PBXT`外键系统进行交互。

### 注意

phpMyAdmin 的其他部分配置存储（例如书签）在`InnoDB、PBXT`或 MySQL 中没有等价物。因此，仍然需要它们来访问完整的 phpMyAdmin 功能集。然而，在 MySQL 5.x 中，支持视图，并且与 phpMyAdmin 的书签有相似之处。

# 使用关系视图定义关系

安装 phpMyAdmin 配置存储后，在`Database`视图和`Table`视图中有更多选项可用。我们现在将在`Table`视图的**Structure**页面中检查**Relation view**链接。

![使用关系视图定义关系](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_10_01.jpg)

这个视图用于：

+   定义当前表格与其他表格的关系

+   选择显示列

我们的目标是在`book`表（包含作者 ID）和`author`表（通过 ID 描述每个作者）之间创建关系。我们从`book`表的“表”视图开始，转到“结构”，然后点击“关系视图”链接。

## 定义内部关系

如果`book`表是以`MyISAM`格式，我们会看到以下屏幕（否则，显示会不同，如后面的“定义外键关系”部分所解释的）：

![定义内部关系](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_10_02.jpg)

这个屏幕允许我们创建“内部关系”（存储在`pma_relation`表中），因为 MySQL 本身对`MyISAM`表没有任何关系概念。每一列旁边的空下拉列表表示没有与任何外键表的关系（链接）。

### 定义关系

我们可以将`book`表的每一列与另一张表的列（或同一张表，因为自引用关系有时是必要的）相关联。界面会在同一数据库的所有表中找到唯一和非唯一键，并以下拉列表的形式呈现这些键。（目前不支持从界面创建到其他数据库的内部关系。）对于“author_id”列的适当选择是从`author`表中选择相应的“id”列。

![定义关系](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_10_03.jpg)

然后点击“保存”，定义将保存在 phpMyAdmin 的配置存储中。要删除关系，只需返回到屏幕，选择空选项，然后点击“保存”。

### 定义显示列

我们的`author`表的主键是`id`，这是我们为主键目的而创造的唯一编号。作者的名字是自然指代作者的方式。在浏览`book`表时看到作者的名字会很有趣。这就是显示列的目的。我们通常应该为每个参与关系的表定义一个显示列，作为外键表。

我们将在“从定义的关系中受益”部分看到这些信息是如何显示的。现在我们转到`author`表的“关系视图”（在这种情况下是外键表），并指定显示列。我们选择“name”作为显示列，然后点击“保存”，如下面的截图所示：

![定义显示列](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_10_04.jpg)

### 注意

phpMyAdmin 只提供为一张表定义一个显示列的选项，并且这一列在使用该表作为外键表的所有关系中都会使用。

现在这个关系的定义已经完成。虽然我们没有将`author`表的任何列与另一张表相关联，但可以这样做。例如，我们可以在这个表中有一个国家代码，并且可以创建到国家表的国家代码的关系。

现在，我们将看到如果我们的表受到`InnoDB`或`PBXT`存储引擎的控制会发生什么。

## 外键关系

`InnoDB`和`PBXT`存储引擎为我们提供了本地外键系统。

### 注意

在本节中，可以选择使用`InnoDB`或`PBXT`存储引擎来完成练习。`InnoDB`已经在文本中选择。

在这个练习中，我们的`book`和`author`表必须使用`InnoDB`存储引擎。我们可以在“表”视图的“操作”页面中进行此操作。

在练习中，为了看到缺少索引的后果，需要采取另一步。我们回到`book`表的“结构”，移除我们在“author_id”和“language”列上创建的组合索引。

`InnoDB`中的外键系统维护相关表之间的完整性。因此，我们无法向`book`表中添加不存在的作者 ID。此外，在对主表执行`DELETE`或`UPDATE`操作时，可以编程执行操作（在我们的情况下是`book`）。

打开`book`表的**结构**页面并进入**关系视图**，现在显示了一个不同的页面：

![外键关系](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_10_05.jpg)

此页面为我们提供以下信息：

+   **author_id**到`author`表有一个内部关系定义。

+   尚未定义任何`InnoDB`关系。

+   当在`InnoDB`中定义了相同的关系时，我们将能够删除内部关系。实际上，悬停在**内部关系**旁边的问号上会显示以下消息：**当存在相应的 FOREIGN KEY 关系时，内部关系是不必要的**。因此，最好将其删除。

在相关键的可能选择中，我们可以看到同一数据库中所有`InnoDB`表中定义的键。 （当前不支持在 phpMyAdmin 中创建跨数据库关系。）当前表中定义的键也会显示，因为自引用关系是可能的。让我们删除**author_id**列的内部关系并单击**保存**。我们的目标是为**author_id**列添加一个`InnoDB 类型`的关系，但是由于此行上出现了**未定义索引！**消息，这是不可能的。这是因为只有在两个列都有索引的情况下，才能在`InnoDB`或`PBXT`中定义外键。

### 注意

有关约束的其他条件在 MySQL 手册中有解释。请参考[`dev.mysql.com/doc/refman/5.1/en/innodb-foreign-key-constraints.html`](http://dev.mysql.com/doc/refman/5.1/en/innodb-foreign-key-constraints.html)。

因此，我们回到`book`表的**结构**页面，并为**author_id**列添加一个普通（非唯一）索引，产生以下屏幕：

![外键关系](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_10_06.jpg)

在**关系视图**中，我们可以再次尝试添加我们想要的关系；这次成功了！

![外键关系](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_10_07.jpg)

我们还可以使用**ON DELETE**和**ON UPDATE**选项设置一些操作。例如，**ON DELETE CASCADE**会使 MySQL 在从父表中删除相应行时自动删除相关（外键）表中的所有行。例如，当父表是`invoices`，而外键表是`invoice‑items`时，这将非常有用。这些选项是 MySQL 本身支持的，因此在 phpMyAdmin 之外进行删除会导致级联删除。

### 注意

如果我们尚未这样做，应该按照“定义显示列”部分的说明为`author`表定义显示列。

### 没有 phpMyAdmin 配置存储的外键

即使未安装配置存储，我们在`InnoDB`或`PBXT`表的**结构**页面上也可以看到**关系视图**链接。这会带我们到一个屏幕，我们可以在这里定义外键，例如`book`表。

请注意，如果选择此选项，无法定义所链接表（在本例中为`author`）的显示列，因为它属于 phpMyAdmin 的配置存储。因此，我们将失去查看外键相关描述的好处。

# 使用设计师定义关系

基于 Ajax 的**设计师**提供了一种以视觉方式管理关系（内部和基于外键的），并为每个表定义显示列的方法。它还可以充当：

+   访问现有表结构和访问表创建页面的菜单

+   如果我们想要一个包含所有表的 PDF 模式管理器

在**设计师**工作区，我们可以在同一面板上处理所有表的关系。另一方面，**关系视图**只显示单个表的关系。

我们可以通过单击**设计师**菜单选项从`数据库`视图访问此功能。

### 注意

如果此菜单选项未出现，则是因为我们尚未按照第一章中描述的方式安装 phpMyAdmin 配置存储。

## 查看界面

**设计师**页面包含主工作区，可以在其中看到表。该工作区将根据我们的表的位置动态增长和缩小。以下截图展示了包含我们的三个表及其之间关系的**设计师**界面：

![查看界面](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_10_08.jpg)

顶部菜单包含图标，将鼠标悬停在上面可以显示其描述。以下表格总结了顶部菜单图标的目标：

| 图标 | 描述 |
| --- | --- |
| **显示/隐藏左侧菜单** | 显示或隐藏左侧菜单。 |
| **保存位置** | 保存工作区的当前状态。 |
| **创建表** | 退出**设计师**并进入对话框以创建表；在单击此按钮之前，我们应该注意保存表的位置。 |
| **创建关系** | 将**设计师**置于创建关系的模式中。 |
| **选择要显示的列** | 指定哪一列代表一个表。 |
| **重新加载** | 在**设计师**之外表的结构发生变化时，刷新表的信息。 |
| **帮助** | 显示有关选择关系的解释。 |
| **Angular 链接/直接链接** | 指定关系链接的形状。 |
| **吸附到网格** | 影响相对于想象网格的表移动行为。 |
| **小/大全部** | 隐藏或显示每个表的列列表。 |
| **切换小/大** | 反转每个表的列显示模式，因为可以使用其角标图标**V**或**>**为每个表选择此模式。 |
| **导入/导出** | 显示一个对话框，以从现有的 PDF 模式定义中导入或导出。 |
| **移动菜单** | 顶部菜单可以向右移动，然后再次返回。 |

单击**显示/隐藏左侧菜单**图标时，会出现一个侧边菜单。其目的是呈现完整的表列表，以便您可以决定哪个表出现在工作区，并启用访问特定表的**结构**页面。在这个例子中，我们选择从工作区中移除**book-copy**表，如下截图所示：

![查看界面](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_10_09.jpg)

如果我们想永久删除它，我们点击**保存位置**顶部图标。该图标还会保存我们的表在工作区上的当前位置。

表可以通过拖动它们的标题栏在工作区上移动，并且可以通过每个表的左上角图标来显示/隐藏表的列列表。在这个列列表中，小图标显示数据类型（数字、文本和日期），并告诉我们这一列是否是主键。

## 定义关系

由于我们已经使用**关系视图**定义了一个关系，我们首先看看如何删除它。**设计师**不允许更改关系。但是，**设计师**允许删除和定义关系。

问号图标显示一个面板，解释了在哪里点击，以便选择要删除的关系。

![定义关系](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_10_10.jpg)

单击关系线以选择它。我们会得到一个确认面板，在上面单击**删除**。

![定义关系](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_10_11.jpg)

然后我们可以继续重新创建它。要做到这一点，我们首先点击**创建关系**图标：

![定义关系](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_10_12.jpg)

然后，光标变成一个短消息，上面写着**选择引用键**。在我们的情况下，引用键是**author**表的**id**列；所以我们把光标放在这个列上并点击它。进行验证，确保我们选择了一个主键或唯一键。

接下来，将光标更改为**选择外键**，将其移动到`book`表的`author_id`列上，然后再次点击。这确认了关系的创建。目前，界面不允许创建复合键（具有多个列）。

### 定义外键关系

删除或定义`InnoDB`或`PBXT`表之间的关系的过程与内部关系相同。唯一的例外是，在创建时，会出现一个不同的确认面板，使我们能够指定`on delete`和`on update`操作。

![定义外键关系](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_10_13.jpg)

## 定义显示列

在工作空间中，`author`表中的`name`列具有特殊的背景颜色。这表示该列作为显示列。我们只需点击**选择要显示的列**图标，然后将短消息**选择要显示的列**拖到另一列上，例如`phone`列。这将更改显示列为该列。如果我们将消息拖到现有的显示列上，我们将删除该列作为表的显示列的定义。

## 导出 PDF 模式

在第十五章中，我们将看到如何为数据库的子集生成 PDF 模式。我们可以将这样一个模式的表坐标导入到**设计师**的工作空间中，反之亦然，将它们导出到 PDF 模式。**导入/导出坐标**图标可用于此目的。

# 受益于定义的关系

在本节中，我们将看到我们目前可以测试的定义关系的好处。其他好处将在第十二章和第十五章中描述。phpMyAdmin 配置存储的其他好处将在第十四章、第十六章和第十八章中出现。

这些好处适用于内部和外键关系。

## 外键信息

让我们浏览`book`表。我们看到相关键**（author_id）**的值现在是链接。将光标移动到任何**author_id**值上会显示作者的名字（由`author`表的显示列定义）。

![外键信息](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_10_14.jpg)

点击**author_id**会带我们到相关的`—author—`表，针对特定的作者：

![外键信息](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_10_15.jpg)

我们可能更喜欢看到所有行的显示列而不是查看键。返回到`book`表，我们可以选择**关系显示列**显示选项并点击**Go**。这会产生一个类似以下截图的屏幕：

![外键信息](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_10_16.jpg)

现在我们通过选择**关系键**并点击**Go**来切换回查看键。

## 外键的下拉列表

在**插入**模式（或**编辑**模式）下显示`book`表，现在每个具有定义关系的列都有可能键的下拉列表。列表包含键和描述（显示列）的两种顺序——键到显示列以及显示列到键。这使我们可以使用键盘输入键或显示列的第一个字母。

![外键的下拉列表](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_10_17.jpg)

### 注意

只有键（在这种情况下为**1**）将存储在`book`表中。显示列仅用于辅助我们。

默认情况下，如果外部表中最多有 100 行，则会出现此下拉列表。这由以下参数控制：

```sql
$cfg['ForeignKeyMaxLimit'] = 100;

```

对于比这更大的外部表，会出现一个不同的窗口——外部表窗口（参见下一节），可以进行浏览。

我们可能希望以不同的方式查看下拉列表中的信息。这里，**John Smith**是内容，**1**是 ID。默认显示由以下代码控制：

```sql
$cfg['ForeignKeyDropdownOrder'] = array( 'content-id', 'id-content');

```

我们可以在定义数组中使用`—content-id`和`id-content—`中的一个或两个字符串，并按照我们喜欢的顺序。因此，将`$cfg['ForeignKeyDropdownOrder']`定义为`array('id-content')`将产生一个只有这些选择的列表：

```sql
1 John Smith
2 Maria Sunshine
3 André Smith

```

## 可浏览的外键表窗口

我们当前的`author`表中只有很少的条目。因此，为了说明这个机制，我们将把`$cfg['ForeignKeyMaxLimit']`设置为一个人为的低数，1。现在在`book`表的**插入**模式中，我们看到一个小表形状的图标和**浏览外键值**链接，用于**author_id**列。这个图标打开另一个窗口，其中会显示`author`表的值和一个**搜索**输入框。左边的值按键值排序（这里是**id**列），右边的值按描述排序。

![可浏览的外键表窗口](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_10_18.jpg)

选择一个值（通过点击键值或描述）会关闭这个窗口，并将值带回**author_id**列。

## 引用完整性检查

我们在第九章中讨论了**操作**页面及其**表维护**部分。在这个练习中，我们假设`book`和`author`表都不受`InnoDB`或`PBXT`存储引擎的控制。如果我们为`author`表定义了内部关系，那么`book`表会出现一个新的选项——**检查引用完整性**。

![引用完整性检查](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_10_19.jpg)

每个定义的关系都会出现一个链接**(author_id -> author.id)**，点击它会开始验证。对于每一行，会验证外键表中相应键的存在性，并报告任何错误。如果结果页面报告零行，那就是好消息！

这个操作存在是因为对于不支持外键的存储引擎下的表，无论是 MySQL 还是 phpMyAdmin 都不会强制执行引用完整性。例如，可以在`book`表中插入无效的**author_id**列的数据。

## 元数据的自动更新

phpMyAdmin 通过在每次通过 phpMyAdmin 对表进行更改时，保持内部关系的元数据同步。例如，重命名作为关系一部分的列会使 phpMyAdmin 在关系的元数据中重命名此列。这保证了内部关系在列名更改后仍然能够正常工作。当删除列或表时也会发生同样的情况。

### 注意

如果从 phpMyAdmin 外部对结构进行更改，元数据应该手动维护。

# 列评论

在 MySQL 4.1 之前，MySQL 结构本身不支持对列添加注释。然而，由于 phpMyAdmin 的元数据，我们可以对列进行注释。然而，自 MySQL 4.1 以来，原生列注释得到了支持。好消息是，对于任何 MySQL 版本，phpMyAdmin 中的列注释始终通过**结构**页面访问，通过编辑每个列的结构。在下面的例子中，我们需要对`book`表的三列进行注释。因此，我们选择它们，然后点击**With selected**旁边的铅笔图标。

![列评论](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_10_20.jpg)

要获得下一个面板，如图所示，我们正在垂直模式下工作。这种模式在第五章中有介绍。我们按照下面的截图输入注释，然后点击**保存**：

![列评论](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_10_21.jpg)

这些注释会出现在各个地方，例如导出文件（参见第六章），PDF 关系模式（参见第十五章），以及浏览模式，如下面的截图所示：

![列评论](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_10_22.jpg)

如果我们不希望注释出现在浏览模式中，我们可以将`$cfg['ShowBrowseComments']`设置为`FALSE`。（默认为`TRUE`。）

列注释也会出现在**结构**页面的工具提示中，列名下划线为虚线。要停用此行为，我们可以将`$cfg['ShowPropertyComments']`设置为`FALSE`。（这个也是默认为`TRUE`。）

## 自动迁移列注释

每当 phpMyAdmin 检测到列注释存储在其元数据中时，它会自动将这些列注释迁移到本机 MySQL 列注释中。

# 总结

本章介绍了如何定义`InnoDB`和非 InnoDB 表之间的关系。它还检查了 phpMyAdmin 的修改行为（当存在关系时）和外键。最后，它涵盖了**设计者**功能，列注释以及如何从表中获取信息。

下一章将介绍输入 SQL 命令的方法，当 phpMyAdmin 的界面不足以完成我们需要的操作时，这些命令非常有用。


# 第十一章：输入 SQL 语句

本章解释了我们如何在 phpMyAdmin 中输入自己的 SQL 语句（查询），以及如何保留这些查询的历史记录。传统上，人们会通过“mysql”命令行客户端与 MySQL 服务器交互，输入 SQL 语句并观察服务器的响应。官方的 MySQL 培训仍然涉及直接向这样的客户端输入语句。

# SQL 查询框

phpMyAdmin 允许我们通过其图形界面执行许多数据库操作。然而，有时我们必须依靠 SQL 查询输入来实现界面不直接支持的操作。以下是两个这样的查询示例：

```sql
SELECT department, AVG(salary) FROM employees GROUP BY department HAVING years_experience > 10;
SELECT FROM_DAYS(TO_DAYS(CURDATE()) +30);

```

要输入这样的查询，可以从 phpMyAdmin 中的多个位置使用 SQL 查询框。

## 数据库视图

当进入“数据库”视图中的“SQL”菜单时，我们会遇到第一个 SQL 查询框。

![数据库视图](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_11_01.jpg)

这个框很简单——我们输入一些有效（希望如此）的 MySQL 语句，然后点击**Go**。在查询文本区域下方，有与书签相关的选择（稍后在第十四章中解释）。通常，我们不必更改标准的 SQL 分隔符，即分号。但是，如果需要，有一个**分隔符**对话框（参见第十七章）。

要在此框中显示默认查询，我们可以使用`$cfg['DefaultQueryDatabase']`配置指令进行设置，默认情况下为空。我们可以在这个指令中放置一个查询，比如`SHOW TABLES FROM @DATABASE@`。这个查询中的`@DATABASE@`占位符将被当前数据库名替换，结果就是在查询框中显示`SHOW TABLES FROM `marc_book``。

## 表视图

在“表”视图的`book`表中，“SQL”菜单中有一个略有不同的框。

![表视图](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_11_02.jpg)

该框已经有一个默认查询，如前一个截图所示。这个默认查询是从`$cfg['DefaultQueryTable']`配置指令生成的，其中包含`SELECT * FROM @TABLE@ WHERE 1`。这里，`@TABLE@`会被当前表名替换。`$cfg['DefaultQueryTable']`中的另一个占位符是`@FIELDS@`。这个占位符将被该表的完整列列表替换，从而生成以下查询：

```sql
SELECT `isbn`, `title`, `page_count`, `author_id`, `language`, `description`, `cover_photo`, `genre`, `date_published`, `stamp`, `some_bits` FROM `book` WHERE 1.

```

`WHERE 1`是一个始终为真的条件。因此，查询可以按原样执行。我们可以用我们想要的条件替换**1**，或者我们可以输入一个完全不同的查询。

由于这个 SQL 框出现在“表”视图中，表名是已知的；因此，phpMyAdmin 在查询框下方显示按钮，允许快速创建包含该表名的常见 SQL 查询。这些按钮生成的大多数查询包含完整的列列表。

### 列选择器

“列”选择器是加快查询生成的一种方式。通过选择一个列并点击箭头**<<**，这个列名就会被复制到查询框中当前的光标位置。在这里，我们选择**author_id**列，删除数字**1**，然后点击**<<**。然后我们添加条件**= 2**，如下截图所示：

![列选择器](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_11_03.jpg)

“再次显示此查询”选项（默认选中）确保查询在执行后仍然保留在框中，如果我们仍然在同一页上。这对于像`UPDATE`或`DELETE`这样影响表但不产生单独结果页面的查询更容易看到。

### 点击查询框

我们可能想要通过`$cfg['TextareaAutoSelect']`配置指令来改变在查询框内点击的行为。它的默认值是`FALSE`，这意味着点击时不会自动选择内容。如果将这个指令更改为`TRUE`，那么第一次点击这个框将选择它的所有内容。（这是一种快速将内容复制到其他地方或从框中删除的方法。）下一次点击将把光标放在点击位置。

# 查询窗口

在第三章中，我们讨论了这个窗口的目的，以及更改一些参数（如尺寸）的过程。这个窗口可以很容易地从导航面板中使用**SQL**图标或**查询窗口**链接打开，如下面的屏幕截图所示，非常方便用于输入查询和测试：

![查询窗口](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_11_04.jpg)

以下屏幕截图显示了出现在主面板上的查询窗口：

![查询窗口](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_11_05.jpg)

屏幕截图中的窗口包含与`表`视图上下文中使用的相同的**列**选择器和**<<**按钮。这个独特的查询窗口只支持启用了 JavaScript 的浏览器。

## 查询窗口选项

**SQL**选项卡是这个窗口中默认的活动选项卡。这来自于配置指令`$cfg['QueryWindowDefTab']`，默认包含`sql`。

如果我们想要另一个选项卡成为默认活动选项卡，我们可以用`files`或`history`替换`sql`。另一个值`full`一次显示所有三个选项卡的内容。

在查询窗口中，我们可以看到一个**不要从窗口外部覆盖此查询**选择的复选框。通常情况下，这个复选框是选中的。如果我们取消选中它，那么我们在生成查询时所做的更改将反映在查询窗口中。这被称为**同步**。例如，从导航或主面板中选择不同的数据库或表会相应地更新查询窗口。然而，如果我们直接在这个窗口中开始输入查询，复选框将被选中以保护其内容并取消同步。这样，这里组成的查询将被锁定和保护。

## 基于会话的 SQL 历史记录

这个功能将我们作为 PHP 会话数据执行的所有成功的 SQL 查询收集起来，并修改查询窗口以使它们可用。这种默认类型的历史记录是临时的，因为`$cfg['QueryHistoryDB']`默认设置为`FALSE`。

## 基于数据库的 SQL 历史记录（永久）

当我们安装了 phpMyAdmin 配置存储（参见第一章）时，就可以使用更强大的历史记录机制。我们现在应该通过将`$cfg['QueryHistoryDB']`设置为`TRUE`来启用这个机制。

在我们从查询框中尝试一些查询之后，一个历史记录就会建立起来，只有从查询窗口中才能看到，如下面的屏幕截图所示：

![基于数据库的 SQL 历史记录（永久）](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_11_06.jpg)

我们可以看到（按相反顺序）最后成功的查询和它们所在的数据库。只有从查询框中输入的查询以及 phpMyAdmin 生成的查询（例如通过点击**浏览**生成的查询）才会保存在这个历史记录中。

它们可以立即执行，**更改**图标可用于将记录的查询插入查询框进行编辑。

将保留的查询数量由`$cfg['QueryHistoryMax']`控制，默认设置为`25`。这个限制不是出于性能原因，而是为了实现一个视觉上不受限制的视图而设置的实际限制。额外的查询在登录时被消除，这个过程传统上被称为**垃圾收集**。查询被存储在`$cfg['Servers'][$i]['history']`中配置的表中。

## 编辑查询

在成功查询的结果页面上，会显示包含执行查询的标题，如下截图所示：

![编辑查询](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_11_07.jpg)

单击**编辑**会打开查询窗口的**SQL**选项卡，并准备修改此查询。这是因为该参数的默认设置如下：

```sql
$cfg['EditInWindow'] = TRUE;

```

当它设置为`FALSE`时，单击**编辑**将不会打开查询窗口；相反，查询将出现在**SQL**页面的查询框内。

单击**内联**会将显示的查询替换为文本区域，在这里可以编辑和提交此查询，而不离开当前结果页面。

# 多语句查询

在 PHP 和 MySQL 编程中，我们可以使用`mysql_query()`函数调用一次只发送一个查询。phpMyAdmin 允许我们使用分号作为分隔符，在一次传输中发送多个查询。假设我们在查询框中输入以下查询：

```sql
INSERT INTO author VALUES (100,'Paul Smith','111-2222');
INSERT INTO author VALUES (101,'Melanie Smith','222-3333');
UPDATE author SET phone='444-5555' WHERE name LIKE '%Smith%';

```

我们将收到以下结果屏幕：

![多语句查询](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_11_08.jpg)

我们通过注释看到受影响的行数，因为`$cfg['VerboseMultiSubmit']`设置为`TRUE`。

让我们再次发送相同的查询列表并观看结果：

![多语句查询](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_11_09.jpg)

收到“重复条目”错误消息是正常的，该消息表示值**100**已经存在。我们看到第一个**INSERT**语句的结果；但是下一个会发生什么？由于`$cfg['IgnoreMultiSubmitErrors']`设置为`FALSE`，告诉 phpMyAdmin 不要忽略多个语句中的错误，因此执行在第一个错误处停止。如果设置为`TRUE`，程序将依次尝试所有语句，我们会看到两个**重复条目**错误。

如果我们尝试多个`SELECT`语句，此功能将无法按预期工作。我们将只看到最后一个`SELECT`语句的结果。

# 漂亮打印（语法高亮）

默认情况下，phpMyAdmin 解析和突出显示其处理的任何 MySQL 语句的各个元素。这由`$cfg['SQP']['fmtType']`控制，默认设置为`'html'`。此模式对每个不同的元素（保留字、变量、注释等）使用特定颜色，如`$cfg['SQP']['fmtColor']`数组中所描述的那样，该数组位于特定主题的`layout.inc.php`文件中。

将`fmtType`设置为`'text'`将删除所有颜色格式，将换行符插入到 MySQL 语句中的逻辑点。最后，将`fmtType`设置为`'none'`将删除所有格式，保留我们的语法不变。

# SQL 验证器

每次 phpMyAdmin 传输查询时，MySQL 服务器会解释它并提供反馈。查询的语法必须遵循 MySQL 规则，这与 SQL 标准不同。但是，遵循 SQL 标准可以确保我们的查询在其他 SQL 实现上可用。

一个免费的外部服务，**Mimer SQL 验证器**，由 Mimer Information Technology AB 提供。它根据 Core SQL-99 规则验证我们的查询并生成报告。验证器可以直接从 phpMyAdmin 使用，并且其主页位于[`developer.mimer.com/validator/index.htm`](http://developer.mimer.com/validator/index.htm)。

### 注意

出于统计目的，此服务会匿名存储接收到的查询。在存储查询时，它会用通用名称替换数据库、表和列名称。查询中的字符串和数字将被替换为通用值，以保护原始信息。

## 系统要求

此验证器作为 SOAP 服务提供。我们的 PHP 服务器必须具有 XML、PCRE 和 SOAP 支持。SOAP 支持由 PHP 扩展或 PEAR 模块提供。如果选择 PEAR 方式，系统管理员在服务器上执行以下命令安装我们需要的模块：

```sql
pear install Net_Socket Net_URL HTTP_Request Mail_Mime Net_DIME SOAP 

```

如果由于某些模块处于测试阶段而导致该命令出现问题，我们可以执行以下命令，安装 SOAP 和其他依赖模块：

```sql
pear -d preferred_state=beta install -a SOAP 

```

## 使验证器可用

必须在`config.inc.php`中配置一些参数。将`$cfg['SQLQuery']['Validate']`设置为`TRUE`可以启用**验证 SQL**链接。

我们还应该启用验证器本身（因为将来的 phpMyAdmin 版本可能会提供其他验证器）。这可以通过将`$cfg['SQLValidator']['use']`设置为`TRUE`来完成。

验证器默认使用匿名验证器帐户访问，配置如下命令：

```sql
$cfg['SQLValidator']['username'] = '';
$cfg['SQLValidator']['password'] = '';

```

相反，如果 Mimer Information Technology 已经为我们提供了一个帐户，我们可以在这里使用该帐户信息。

## 验证器结果

验证器返回两种报告之一，一种是查询符合标准的，另一种是不符合标准的。

### 符合标准的查询

我们将尝试一个简单的查询：`SELECT COUNT(*) FROM book`。像往常一样，我们在查询框中输入此查询并发送。在结果页面上，我们现在看到了一个额外的链接——**验证 SQL**，如下截图所示：

![符合标准的查询](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_11_10.jpg)

点击**验证 SQL**会生成如下截图所示的报告：

![符合标准的查询](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_11_11.jpg)

我们可以选择点击**跳过验证 SQL**来查看我们的原始查询。

### 不符合标准的查询

让我们尝试另一个在 MySQL 中正确工作的查询：`SELECT * FROM book WHERE language = 'en'`。将其发送到验证器会生成如下截图所示的报告：

![不符合标准的查询](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-pma34-eff-mysql-mgt/img/7782_11_12.jpg)

每当验证器发现问题时，它会在错误点添加诸如**{error: 1}**的消息，并在报告中添加脚注。在此查询中，**language**列名是非标准的。因此，验证器告诉我们在此处期望标识符。关于使用`LIMIT`子句的非标准错误也被报告，这是 phpMyAdmin 添加到查询中的。

另一个情况是反引号。如果我们只是点击**浏览**`book`表，phpMyAdmin 会生成`SELECT * FROM `book``，用反引号括起表名。这是 MySQL 保护标识符的方式，标识符可能包含特殊字符，如空格、国际字符或保留字。然而，将此查询发送给验证器会显示反引号不符合标准 SQL。我们甚至可能会得到两个错误，每个反引号一个。

# 摘要

本章帮助我们理解了查询框的目的，并告诉我们在哪里找到它们。它还概述了如何使用列选择器、查询窗口选项、如何获取输入命令的历史记录、多语句查询，最后，如何使用 SQL 验证器。

下一章将展示如何通过 phpMyAdmin 的查询生成器生成多表查询而无需输入太多内容。
