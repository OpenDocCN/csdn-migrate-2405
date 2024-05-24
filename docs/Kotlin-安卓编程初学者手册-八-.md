# Kotlin 安卓编程初学者手册（八）

> 原文：[`zh.annas-archive.org/md5/507BA3297D2037C2888F887A989A734A`](https://zh.annas-archive.org/md5/507BA3297D2037C2888F887A989A734A)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第二十七章：Android 数据库

如果我们要制作具有重要功能的应用程序，几乎可以肯定我们需要一种方式来管理、存储和过滤大量数据。

使用 JSON 可以高效地存储大量数据，但当我们需要有选择地使用数据而不仅仅限制在“保存所有”和“加载所有”的选项时，我们需要考虑其他可用的选项。

一个好的计算机科学课程可能会教授处理数据排序和过滤所需的算法，但涉及的工作量会相当大，我们能否想出与为我们提供 Android API 的人一样好的解决方案呢？

因此，通常情况下，使用 Android API 中提供的解决方案是有意义的。正如我们所见，`JSON`和`SharedPreferences`类有其用途，但在某个时候，我们需要转向使用真正的数据库来解决现实世界的问题。Android 使用 SQLite 数据库管理系统，而且如你所期望的那样，有一个 API 可以尽可能地简化它。

在本章中，我们将做以下事情：

+   确切地了解什么是数据库

+   学习 SQL 和 SQLite 是什么

+   学习 SQL 语言的基础知识

+   查看 Android SQLite API

+   编写上一章开始的 Age Database 应用程序

# 数据库 101

让我们回答一大堆与数据库相关的问题，然后我们就可以开始制作使用 SQLite 的应用程序。

那么，什么是数据库？

## 什么是数据库？

**数据库**既是一个存储的地方，也是检索、存储和操作数据的手段。在学习如何使用数据库之前，能够形象地想象一个数据库是很有帮助的。实际上，数据库内部的结构因所涉及的数据库而异。SQLite 实际上将所有数据存储在一个单独的文件中。

然而，如果我们将数据想象成电子表格，有时是多个电子表格，我们的理解将会大大有助。我们的数据库，就像电子表格一样，将被划分为代表不同类型数据的多个列，以及代表数据库条目的行。

想象一个包含姓名和考试成绩的数据库。看一下这个数据的可视化表示，我们可以想象它在数据库中的样子：

![什么是数据库？](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_27_01.jpg)

然而请注意，这里有一列额外的数据——一个**ID**列。随着我们的学习，我们将会更多地讨论这个。这种类似电子表格的结构被称为**表**。如前所述，数据库中可能有多个表。表的每一列都有一个名称，可以在与数据库交互时引用。当我们向数据库提问时，我们说我们正在**查询**数据库。

## 什么是 SQL？

**SQL**代表**结构化查询语言**。这是用于与数据库进行交互的语法。

## 什么是 SQLite？

SQLite 是 Android 所青睐的整个数据库系统的名称，它有自己的 SQL 版本。SQLite 版本的 SQL 需要稍微不同是因为数据库具有不同的特性。

接下来的 SQL 语法基础知识将专注于 SQLite 版本。

# SQL 语法基础知识

在学习如何在 Android 中使用 SQLite 之前，我们需要首先学习如何在通用平台上使用 SQLite 的基础知识。

让我们看一些示例 SQL 代码，可以直接在 SQLite 数据库上使用，而不需要任何 Kotlin 或 Android 类，然后我们可以更容易地理解我们的 Kotlin 代码在后续的操作中在做什么。

## SQLite 示例代码

SQL 有关键字，就像 Kotlin 一样，会引发一些事件发生。以下是我们很快将要使用的一些 SQL 关键字的示例：

+   `INSERT`：允许我们向数据库中添加数据

+   `DELETE`：允许我们从数据库中删除数据

+   `SELECT`：允许我们从数据库中读取数据

+   `WHERE`：允许我们指定与我们想要从中`INSERT`、`DELETE`或`SELECT`的特定条件匹配的数据库部分

+   `FROM`：用于指定数据库中的表或列名

### 注意

SQLite 关键字远不止这些，要获得全面的列表，请查看此链接：[`sqlite.org/lang_keywords.html`](https://sqlite.org/lang_keywords.html)。

除了关键字，SQL 还有**类型**。一些 SQL 类型的示例如下：

+   **integer**：正是我们存储整数所需的

+   **text**：非常适合存储简单的名称或地址

+   **real**：用于大型浮点数

### 注意

SQLite 类型远不止这些，要获得全面的列表，请查看此链接：[`www.sqlite.org/datatype3.html`](https://www.sqlite.org/datatype3.html)。

让我们看看如何结合这些类型和关键字来创建表，并使用完整的 SQLite 语句添加、删除、修改和读取数据。

### 创建表

一个完全合理的问题是为什么我们不先创建一个新的数据库。原因是每个应用程序默认都可以访问 SQLite 数据库。该数据库对该应用程序是私有的。以下是我们将使用的语句在该数据库中创建表。我已经突出显示了一些部分，以使语句更清晰：

```kt
create table StudentsAndGrades 
   _ID integer primary key autoincrement not null,
   name text not null,
 score int;
```

上面的代码创建了一个名为`StudentsAndGrades`的表，其中有一个**integer**行**id**，每次添加一行数据时都会自动增加（递增）。

该表还将有一个`name`列，类型为`text`，不能是空的（`not null`）。

它还将有一个`score`列，类型为`int`。另外，请注意语句以分号结束。

### 向数据库插入数据

以下是我们如何向该数据库插入新的数据行：

```kt
INSERT INTO StudentsAndGrades
   (name, score)
   VALUES
   ("Bart", 23);
```

上面的代码向数据库添加了一行。在前面的语句之后，数据库将有一个条目，其值为（1、"Bart"、23），对应列为（_ID、name 和 score）。

以下是我们如何向该数据库插入另一行新数据：

```kt
INSERT INTO StudentsAndGrades
   (name, score)
   VALUES
   ("Lisa", 100);
```

上面的代码为列（_ID、name 和 score）添加了新的数据行（2、"Lisa"、100）。

我们类似电子表格的结构现在看起来像下面的图表：

![向数据库插入数据](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_27_02.jpg)

### 从数据库中检索数据

以下是我们如何从数据库中访问所有行和列：

```kt
SELECT * FROM StudentsAndGrades;

```

上面的代码要求每一行和每一列。`*`符号可以读作**all**。

我们也可以更加选择性，如下面的代码所示：

```kt
SELECT score FROM StudentsAndGrades
 where name = "Lisa";

```

上面的代码只会返回`100`，当然，这是与名称 Lisa 相关联的分数。

### 更新数据库结构

我们甚至可以在创建表并添加数据后添加新列。就 SQL 而言，这很简单，但可能会对已发布的应用程序中用户的数据造成一些问题。下一个语句添加了一个名为`age`的新列，类型为`int`：

```kt
ALTER TABLE StudentsAndGrades
            ADD 
     age int;
```

数据类型、关键字和使用它们的方式远不止我们迄今所见。接下来，让我们看看 Android SQLite API，我们将开始看到如何使用我们的新的 SQLite 技能。

# Android SQLite API

Android API 以多种方式使我们相当容易地使用应用程序的数据库。我们需要熟悉的第一个类是`SQLiteOpenHelper`。

## SQLiteOpenHelper 和 SQLiteDatabase

`SQLiteDatabase`类是表示实际数据库的类。然而，`SQLiteOpenHelper`类是大部分操作发生的地方。这个类将使我们能够访问数据库并初始化`SQLiteDatabase`的实例。

此外，我们将从中继承的`SQLiteOpenHelper`类在*Age database*应用程序中有两个要重写的函数。首先，它有一个`onCreate`函数，第一次使用数据库时会调用，因此我们会在其中加入我们的 SQL 以创建表结构是有意义的。

我们必须重写的另一个函数是`onUpgrade`，您可能已经猜到，当我们升级数据库（`ALTER`其结构）时会调用它。

## 构建和执行查询

随着数据库结构变得更加复杂和我们的 SQL 知识的增长，我们的 SQL 语句会变得相当长和笨拙。语法错误或拼写错误的可能性很高。

我们将帮助克服这种复杂性的方法是将查询从各个部分构建成一个`String`。然后我们可以将该`String`传递给执行查询的函数（我们很快就会看到）。

此外，我们将使用`String`实例来表示表和列名称，因此我们不会与它们混淆。

例如，我们可以在`companion`对象中声明以下`String`实例，它们将代表之前虚构示例中的表名和列名。请注意，我们还将为数据库本身命名，并为其也有一个`String`：

```kt
companion object {
   /*
   Next, we have a const string for
   each row/table that we need to refer to both
   inside and outside this class
   */

   const val DB_NAME = "MyCollegeDB";
   const val TABLE_S_AND_G = "StudentsAndGrades";

   const val TABLE_ROW_ID = "_id";
   const val TABLE_ROW_NAME = "name";
   const val TABLE_ROW_SCORE = "score";

}
```

然后我们可以在下一个示例中构建这样的查询。以下示例向我们的假想数据库添加了一个新条目，并将 Kotlin 变量合并到了 SQL 语句中：

```kt
val name = "Smit";
val score = 95;

// Add all the details to the table
val query = "INSERT INTO " + TABLE_S_AND_G + " (" +
         TABLE_ROW_NAME + ", " +
         TABLE_ROW_SCORE +
         ") " +
         "VALUES (" +
         "'" + name + "'" + ", " +
         score +
         ");"
```

请注意，在前面的代码中，常规的 Kotlin 变量`name`和`score`被突出显示。之前的名为`query`的`String`现在是 SQL 语句，与此完全相同：

```kt
INSERT INTO StudentsAndGrades (
   name, score)
   VALUES ('Smit',95);
```

### 提示

要继续学习 Android 编程，不一定要完全掌握前两个代码块。但是，如果您想构建自己的应用程序并构造完全符合您需求的 SQL 语句，那么理解这两个代码块将有所帮助。为什么不学习前两个代码块，以便分辨出与 SQL 语法相关的`String`部分之间用单引号`'`连接的差异呢？

在输入查询时，Android Studio 会提示我们变量的名称，这样错误的可能性就会大大降低，尽管它比简单输入查询更冗长。

现在，我们可以使用之前介绍的类来执行查询：

```kt
// This is the actual database
private val db: SQLiteDatabase

// Create an instance of our internal CustomSQLiteOpenHelper class
val helper = CustomSQLiteOpenHelper(context)

// Get a writable database
db = helper.writableDatabase

// Run the query
db.execSQL(query)
```

在向数据库添加数据时，我们将使用`execSQL`，就像之前的代码中一样，而在从数据库获取数据时，我们将使用`rawQuery`函数，如下所示：

```kt
Cursor c = db.rawQuery(query, null)
```

注意`rawQuery`函数返回`Cursor`类型的对象。

### 提示

与 SQLite 交互的方式有几种，它们各自都有优缺点。我们选择使用原始 SQL 语句，因为这样做完全透明，同时加强了我们对 SQL 语言的了解。

## 数据库游标

除了让我们访问数据库的类和允许我们执行查询的函数之外，还有一个问题，那就是我们从查询中得到的结果的格式。

幸运的是，有`Cursor`类。我们所有的数据库查询都将返回`Cursor`类型的对象。我们可以使用`Cursor`类的函数有选择地访问从查询返回的数据，就像下面的代码一样：

```kt
Log.i(c.getString(1), c.getString(2))
```

先前的代码将在 logcat 窗口中输出查询返回结果的前两列中存储的两个值。确定我们当前正在读取的返回数据的哪一行是`Cursor`对象本身确定的。

我们可以访问`Cursor`对象的各种函数，包括`moveToNext`函数，它会将`Cursor`移动到下一行以便读取：

```kt
c.moveToNext()

/*
   This same code now outputs the data in the
   first and second column of the returned 
   data but from the SECOND row.
*/

Log.i(c.getString(1), c.getString(2))
```

在某些情况下，我们将能够将`Cursor`绑定到我们 UI 的一部分（例如`RecyclerView`），就像我们在*Note to self*应用程序中使用`ArrayList`一样，并且只需将一切交给 Android API。

`Cursor`类中还有许多有用的函数，其中一些我们很快就会看到。

### 提示

这篇介绍 Android SQLite API 实际上只是触及了它的能力表面。随着我们进一步进行，我们会遇到更多的函数和类。然而，如果您的应用想法需要复杂的数据管理，进一步研究是值得的。

现在，我们可以看到所有这些理论是如何结合在一起的，以及我们将如何在 Age 数据库应用程序中构建我们的数据库代码的结构。

# 编写数据库类

在这里，我们将把我们迄今学到的一切付诸实践，并完成编写 Age 数据库应用程序。在我们之前的部分的`Fragment`类可以与共享数据库进行交互之前，我们需要一个处理与数据库的交互和创建的类。

我们将创建一个通过实现`SQLiteOpenHelper`来管理我们的数据库的类。它还将在`companion object`中定义一些`String`变量，以表示表的名称和其列。此外，它将提供一堆辅助函数，我们可以调用这些函数来执行所有必要的查询。在必要时，这些辅助函数将返回一个`Cursor`对象，我们可以用来显示我们检索到的数据。如果我们的应用需要发展，添加新的辅助函数将是微不足道的：

创建一个名为`DataManager`的新类，并添加`companion object`、构造函数和`init`块：

### 提示

我们在第二十五章中讨论了`companion object`，*使用分页和滑动的高级 UI*

```kt
class DataManager(context: Context) {

    // This is the actual database
    private val db: SQLiteDatabase

    init {
        // Create an instance of our internal
        // CustomSQLiteOpenHelper class
        val helper = CustomSQLiteOpenHelper(context)
        // Get a writable database
        db = helper.writableDatabase
    }

    companion object {
        /*
        Next, we have a const string for
        each row/table that we need to refer to both
        inside and outside this class
        */

        const val TABLE_ROW_ID = "_id"
        const val TABLE_ROW_NAME = "name"
        const val TABLE_ROW_AGE = "age"

        /*
        Next, we have a private const strings for
        each row/table that we need to refer to just
        inside this class
        */

        private const val DB_NAME = "address_book_db"
        private const val DB_VERSION = 1
        private const val TABLE_N_AND_A = "names_and_addresses"
    }
}
```

### 注意

我将数据库和表命名为可能会发展成一个地址簿应用，还可以跟踪年龄和生日。

前面的代码为我们提供了构建查询的所有方便的`String`实例，并声明和初始化了我们的数据库和辅助类。

现在，我们可以添加我们将从我们的`Fragment`类中访问的辅助函数；首先是`insert`函数，它根据传入函数的`name`和`age`参数执行`INSERT` SQL 查询。

将`insert`函数添加到`DataManager`类中：

```kt
// Insert a record
fun insert(name: String, age: String) {
  // Add all the details to the table
  val query = "INSERT INTO " + TABLE_N_AND_A + " (" +
               TABLE_ROW_NAME + ", " +
               TABLE_ROW_AGE +
               ") " +
               "VALUES (" +
               "'" + name + "'" + ", " +
               "'" + age + "'" +
               ");"

  Log.i("insert() = ", query)

  db.execSQL(query)
}
```

下一个名为`delete`的函数将从数据库中删除记录，如果它在`name`列中具有与传入的`name`参数相匹配的值。它使用 SQL 的`DELETE`关键字来实现这一点。

将`delete`函数添加到`DataManager`类中：

```kt
// Delete a record
fun delete(name: String) {

   // Delete the details from the table
   // if already exists
   val query = "DELETE FROM " + TABLE_N_AND_A +
               " WHERE " + TABLE_ROW_NAME +
               " = '" + name + "';"

   Log.i("delete() = ", query)

   db.execSQL(query)

}
```

接下来，我们有`selectAll`函数，它也如其名称所示。它使用`SELECT`查询来实现这一点，使用`*`参数，这相当于单独指定所有列。另外，请注意该函数返回一个`Cursor`，我们将在一些`Fragment`类中使用。

将`selectAll`函数添加到`DataManager`类中，如下所示：

```kt
// Get all the records
fun selectAll(): Cursor {
   return db.rawQuery("SELECT *" + " from " +
               TABLE_N_AND_A, null)
}
```

现在，我们添加一个`searchName`函数，它具有一个`String`参数，用于用户想要搜索的名称。它还返回一个`Cursor`对象，其中包含找到的所有条目。请注意，SQL 语句使用`SELECT`、`FROM`和`WHERE`来实现这一点：

```kt
// Find a specific record
fun searchName(name: String): Cursor {
    val query = "SELECT " +
                 TABLE_ROW_ID + ", " +
                 TABLE_ROW_NAME +
                 ", " + TABLE_ROW_AGE +
                 " from " +
                 TABLE_N_AND_A + " WHERE " +
                 TABLE_ROW_NAME + " = '" + name + "';"

   Log.i("searchName() = ", query)

   return db.rawQuery(query, null)
}
```

最后，对于`DataManager`类，我们创建一个`inner`类，它将是我们的`SQLiteOpenHelper`的实现。这是一个最基本的实现。

我们有一个构造函数，接收一个`Context`对象、数据库名称和数据库版本。

我们还重写了`onCreate`函数，其中包含创建具有`_ID`、`name`和`age`列的数据库表的 SQL 语句。

`onUpgrade`函数在这个应用程序中被故意留空，但仍然需要存在，因为当我们从`SQLiteOpenHelper`继承时，它是合同的一部分。

将内部的`CustomSQLiteOpenHelper`类添加到`DataManager`类中：

```kt
// This class is created when 
// our DataManager class is instantiated
private inner class CustomSQLiteOpenHelper(
         context: Context)
     : SQLiteOpenHelper(
           context, DB_NAME,
           null, DB_VERSION) {

  // This function only runs the first
  // time the database is created
  override fun onCreate(db: SQLiteDatabase) {

        // Create a table for photos and all their details
        val newTableQueryString = ("create table "
              + TABLE_N_AND_A + " ("
              + TABLE_ROW_ID
              + " integer primary key autoincrement not null,"
              + TABLE_ROW_NAME
              + " text not null,"
              + TABLE_ROW_AGE
              + " text not null);")

        db.execSQL(newTableQueryString)
  }

  // This function only runs when we increment DB_VERSION
  override fun onUpgrade(db: SQLiteDatabase,
                     oldVersion: Int,
                     newVersion: Int) {

  }

}
```

现在，我们可以在我们的`Fragment`类中添加代码来使用我们的新`DataManager`类。

# 编写 Fragment 类以使用 DataManager 类

将此突出显示的代码添加到`InsertFragment`类中，以更新`onCreateView`函数，如下所示：

```kt
val view = inflater.inflate(
         R.layout.content_insert,
         container,
         false)

// Database and UI code goes here in next chapter
val dm = DataManager(activity!!)

val btnInsert = view.findViewById(R.id.btnInsert) as Button
val editName = view.findViewById(R.id.editName) as EditText
val editAge = view.findViewById(R.id.editAge) as EditText

btnInsert.setOnClickListener(
            {
 dm.insert(editName.text.toString(),
 editAge.text.toString())
            }
)

return view
```

在代码中，我们获取了`DataManager`类的一个实例和每个 UI 小部件的引用。然后，在按钮的`onClick`函数中，我们使用`insert`函数向数据库添加新的名称和年龄。要插入的值来自两个`EditText`小部件。

将此突出显示的代码添加到`DeleteFragment`类中，以更新`onCreateView`函数：

```kt
val view = inflater.inflate(
         R.layout.content_delete,
         container,
         false)

// Database and UI code goes here in next chapter
val dm = DataManager(activity!!)

val btnDelete = 
 view.findViewById(R.id.btnDelete) as Button
val editDelete = 
 view.findViewById(R.id.editDelete) as EditText

btnDelete.setOnClickListener(
 {
 dm.delete(editDelete.text.toString())
 }
)

return view
```

在`DeleteFragment`类中，我们创建了`DataManager`类的一个实例，然后从布局中获取了`EditText`和`Button`的引用。当点击按钮时，将调用`delete`函数，传入`EditText`中的任何文本值。删除函数会在我们的数据库中搜索匹配项，如果找到，则删除它。

将此突出显示的代码添加到`SearchFragment`类中，以更新`onCreateView`函数：

```kt
val view = inflater.inflate(R.layout.content_search,
         container,
         false)

// Database and UI code goes here in next chapter
val btnSearch = view.findViewById(R.id.btnSearch) as Button
val editSearch = view.findViewById(R.id.editSearch) as EditText
val textResult = view.findViewById(R.id.textResult) as TextView

// This is our DataManager instance
val dm = DataManager(activity!!)

btnSearch.setOnClickListener(
 {
 val c = dm.searchName(editSearch.text.toString())

 // Make sure a result was found 
 // before using the Cursor
 if (c.count > 0) {
 c.moveToNext()
 textResult.text =
 "Result = ${c.getString(1)} - ${c.getString(2)}"
 }
 }
)

return view
```

与我们为所有不同的`Fragment`类所做的一样，我们创建了`DataManager`的一个实例，并获取了布局中所有不同 UI 小部件的引用。在按钮的`onClick`函数中，使用`searchName`函数，传入`EditText`中的值。如果数据库在`Cursor`中返回结果，那么`TextView`使用其`text`属性来输出结果。

将此突出显示的代码添加到`ResultsFragment`类中，以更新`onCreateView`函数：

```kt
val view = inflater.inflate(R.layout.content_results,
         container,
         false)

// Database and UI code goes here in next chapter
// Create an instance of our DataManager
val dm = DataManager(activity!!)

// Get a reference to the TextView 
// to show the results in
val textResults = 
 view.findViewById(R.id.textResults) as TextView

// Create and initialize a Cursor 
// with all the results in
val c = dm.selectAll()

// A String to hold all the text
var list = ""

// Loop through the results in the Cursor
while (c.moveToNext()) {
 // Add the results to the String
 // with a little formatting
 list += c.getString(1) + " - " + c.getString(2) + "\n"
}

// Display the String in the TextView
textResults.text = list

return view
```

在这个类中，在任何交互发生之前，使用`selectAll`函数将`Cursor`对象加载了数据。然后，通过连接结果将`Cursor`的内容输出到`TextView`中。连接中的`\n`是在`Cursor`中的每个结果之间创建新行的内容。

# 运行年龄数据库应用程序

让我们运行一些我们的应用程序功能，以确保它按预期工作。首先，我使用**插入**菜单选项向数据库添加了一个新名称：

![运行年龄数据库应用程序](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_27_03.jpg)

然后，我通过查看**结果**选项确认它确实存在：

![运行年龄数据库应用程序](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_27_04.jpg)

然后，我使用**删除**菜单选项，再次查看**结果**选项，以检查我选择的名称是否确实被删除了：

![运行年龄数据库应用程序](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_27_05.jpg)

接下来，我搜索了一个我知道存在的名称来测试**搜索**功能：

![运行年龄数据库应用程序](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_27_06.jpg)

让我们回顾一下本章中我们所做的事情。

# 总结

在本章中，我们涵盖了很多内容。我们学习了关于数据库，特别是 Android 应用程序的数据库 SQLite。我们练习了使用 SQL 语言与数据库进行通信和查询的基础知识。

我们已经看到了 Android API 如何帮助我们使用 SQLite 数据库，并实现了我们的第一个具有数据库的工作应用程序。

就是这样了，但请看接下来的简短最终章节。


# 第二十八章：在你离开之前快速交谈

我们的旅程就快结束了。这一章只是一些你可能在匆忙制作自己的应用程序之前想要看看的想法和指针：

+   发布

+   制作你的第一个应用程序

+   继续学习

+   谢谢

# 发布

你已经足够了解如何设计你自己的应用程序。你甚至可以对书中的应用程序进行一些修改，并添加许多新功能。

我决定不提供关于在 Google Play 商店发布的逐步指南，因为这些步骤并不复杂。然而，它们相当深入和有点费力。大部分步骤涉及输入关于你和你的应用的个人信息和图片。这样的教程可能会读起来像下面这样：

1.  填写这个文本框。

1.  现在，填写那个文本框。

1.  上传这张图片。

1.  等等。

不太有趣或有用。

要开始，你只需要访问[`play.google.com/apps/publish`](https://play.google.com/apps/publish)并支付一笔适度的费用（大约 25 美元），具体金额取决于你所在地区的货币。这样你就可以终身发布应用程序了。

### 提示

如果你想要一个发布的清单，请查看以下网址：[`developer.android.com/distribute/best-practices/launch/launch-checklist.html`](https://developer.android.com/distribute/best-practices/launch/launch-checklist.html)。你会发现这个过程很直观（尽管非常冗长）。

# 制作应用程序！

如果你只是把这一件事付诸实践，你就可以忽略本章中的其他内容：

### 提示

不要等到你成为专家才开始制作应用程序！

开始制作你的梦想应用程序，那个拥有所有功能的应用程序，将会在 Google Play 上风靡一时。然而，一个简单的建议是：先做一些规划！不要太多，然后开始。

在一旁有一些更小、更容易实现的项目；你可以向朋友和家人展示这些项目，并探索对你来说是新的 Android 领域。如果你对这些应用程序有信心，你可以将它们上传到 Google Play。如果你担心它们会受到评论者的评价，那就让它们免费，并在描述中加上“只是一个原型”之类的说明。

如果你的经历和我的一样，你会发现当你阅读、学习和制作应用程序时，你会发现你的梦想应用程序可以在许多方面得到改进，你可能会被启发去重新设计它，甚至重新开始。

当你这样做时，我可以保证，下一次你构建它时，你会用一半的时间做到两倍好，至少！

# 继续学习

如果你觉得自己已经走了很长的路，你是对的。然而，总是有更多的东西可以学习。

## 继续阅读

你会发现，当你制作你的第一个应用程序时，你会突然意识到你的知识中存在一个需要填补的空白，以使某些功能得以实现。这是正常的，也是可以预料的；不要让它吓到你。想想如何描述这个问题，并在谷歌上搜索解决方案。

你可能会发现项目中的特定类会超出实际可维护的大小。这表明有更好的方式来构建事物，而且可能已经有现成的设计模式可以让你的生活更轻松。

为了预防这种几乎不可避免的情况，为什么不立即学习一些模式呢？一个很好的来源是[`proandroiddev.com/kotlin-design-patterns-8e152540ee2c`](https://proandroiddev.com/kotlin-design-patterns-8e152540ee2c)。

## GitHub

GitHub 允许你搜索和浏览其他人编写的代码，并查看他们是如何解决问题的。这很有用，因为看到类的文件结构，然后深入其中，通常会显示如何从一开始规划你的应用程序，并防止你走上错误的道路。你甚至可以获得一个 GitHub 应用程序，让你可以在手机或平板电脑上舒适地做到这一点。

你甚至可以配置安卓工作室来保存和分享你的项目到 GitHub。例如，在主页[www.github.com](http://www.github.com)上搜索“Android fragment”，你会看到超过 1000 个相关项目，你可以浏览，如下所示：

![GitHub](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_28_01.jpg)

## StackOverflow

如果遇到困难，出现奇怪的错误，或者莫名其妙的崩溃，通常最好的去处是谷歌。这样做，你会惊讶地发现 StackOverflow 似乎经常出现在搜索结果中；而且理由充分。

StackOverflow 允许用户发布问题描述和示例代码，社区可以回答。然而根据我的经验，很少需要发布问题，因为几乎总会有人遇到完全相同的问题。

StackOverflow 对于最前沿的问题特别有用。如果新的 Android Studio 版本有 bug，或者新的 Android API 版本似乎没有按照预期运行，那么你几乎可以肯定全球数千名开发者也遇到了同样的问题。然后，一些聪明的编程人员，通常来自安卓开发团队，会给出答案。

StackOverflow 也适合轻松阅读。打开[www.stackoverflow.com](http://www.stackoverflow.com)首页，在搜索框中输入“Android”，你会看到 StackOverflow 社区最新的问题列表：

![StackOverflow](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_28_02.jpg)

我并不是建议你立即开始尝试回答所有问题，但阅读问题和建议会教会你很多，你可能会发现，往往你有解决方案，或者至少有解决方案的想法。

## 安卓用户论坛

此外，值得注册一些安卓论坛，偶尔访问，了解用户的热门话题和趋势。我没有列出任何论坛，因为只需要快速搜索即可。

如果你是认真的，你可以参加一些安卓会议，与成千上万的其他开发者交流并参加讲座。如果你感兴趣，可以搜索 Droidcon、Android developer Days 或 GDG DevFest。

## 更高层次的学习

你现在可以阅读更多其他安卓书籍。我在本书开头提到，几乎没有一本书可以教会没有 Kotlin 经验的读者安卓编程。这就是我写这本书的原因。

现在你对面向对象编程和 Kotlin 有了很好的理解，还有对应用设计和安卓 API 的简要介绍，你可以阅读安卓“初学者”书籍，这些书籍适合已经知道如何在 Kotlin 中编程的人，就像你现在一样。

这些书中充满了很多好例子，你可以构建或者仅仅阅读，以加强你在本书中学到的知识，以不同的方式使用你的知识，当然，也学到一些全新的东西。

也许值得阅读一些纯 Kotlin 书籍。也许很难相信，在浏览了大约 750 页之后，Kotlin 还有很多内容没有时间在这里覆盖。

我可以列举一些书名，但在亚马逊上有最多积极评价的书籍往往值得探索。

# 我的其他渠道

请保持联系：

+   [www.gamecodeschool.com](http://www.gamecodeschool.com)

+   [www.facebook.com/gamecodeschool](http://www.facebook.com/gamecodeschool)

+   [www.twitter.com/gamecodeschool](http://www.twitter.com/gamecodeschool)

+   [www.youtube.com/channel/UCY6pRQAXnwviO3dpmV258Ig/videos](http://www.youtube.com/channel/UCY6pRQAXnwviO3dpmV258Ig/videos)

+   [www.linkedin.com/in/gamecodeschool](http://www.linkedin.com/in/gamecodeschool)

# 再见，谢谢

写这本书让我很开心。我知道这是陈词滥调，但也是真的。然而最重要的是，我希望你能从中获得一些收获，并将其作为你未来编程之路的一个跳板。

也许你正在阅读这本书是为了好玩，或者为了发布一个应用程序而感到自豪，或者是作为编程工作的一个跳板，或者你真的会开发那个风靡谷歌应用商店的应用程序。

无论如何，非常感谢你购买这本书，我祝愿你在未来的努力中一切顺利。

我认为每个人都有一个应用程序隐藏在内心深处，你所需要做的就是努力工作，把它释放出来。


# 附录 A. 您可能喜欢的其他书籍

如果您喜欢这本书，您可能会对 Packt 的其他书感兴趣：

![您可能喜欢的其他书籍](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/BackMatter1.jpg)

**Android 9 开发食谱-第三版**

Rick Boyer

ISBN：978-1-78899-121-6

+   使用最新的 Android 框架开发应用程序，同时保持与支持库的向后兼容性

+   使用从图形，动画和多媒体配方中获得的知识创建引人入胜的应用程序

+   通过简洁的步骤解决特定问题，帮助您更快地完成项目

+   使用最新的 Google Play 服务 API 示例为您自己的应用程序添加位置感知

+   为您的应用程序利用 Google 语音识别 API

![您可能喜欢的其他书籍](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/BackMatter2.jpg)

**Kotlin 编程食谱**

Aanand Shekhar Roy，Rashi Karanpuria

ISBN：978-1-78847-214-2

+   了解 Kotlin 编程的基础知识和面向对象的概念

+   发掘 Kotlin 集合框架的全部潜力

+   在 Android 中使用 SQLite 数据库，进行网络调用并在网络上获取数据

+   使用 Kotlin 的 Anko 库进行高效快速的 Android 开发

+   发现 Kotlin 的一些最佳功能：Lambda 和委托

+   设置 Web 服务开发环境，编写 Servlet 并使用 Kotlin 构建 RESTful 服务

+   学习如何编写单元测试，集成测试和仪器/验收测试

# 留下评论-让其他读者知道您的想法

请通过在购买书籍的网站上留下评论与其他人分享您对这本书的想法。如果您从亚马逊购买了这本书，请在该书的亚马逊页面上留下诚实的评论。这对其他潜在读者来说非常重要，他们可以看到并使用您的公正意见来做出购买决策，我们可以了解我们的客户对我们的产品的看法，我们的作者可以看到您对他们与 Packt 合作创建的标题的反馈。这只需要花费您几分钟的时间，但对其他潜在客户，我们的作者和 Packt 都是有价值的。谢谢！
