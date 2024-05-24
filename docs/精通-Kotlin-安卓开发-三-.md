# 精通 Kotlin 安卓开发（三）

> 原文：[`zh.annas-archive.org/md5/5ADF07BDE12AEC5E67245035E25F68A5`](https://zh.annas-archive.org/md5/5ADF07BDE12AEC5E67245035E25F68A5)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：使用数据库

在上一章中，我们获得了访问 Android 系统功能所需的关键权限。在我们的情况下，我们获得了位置权限。在本章中，我们将通过向数据库插入数据来继续。我们将插入来自 Android 位置提供程序的位置数据。为此，我们将定义适当的数据库模式和管理类。我们还将定义用于访问位置提供程序以获取位置数据的类。

在本章中，我们将涵盖以下主题：

+   SQLite 简介

+   描述数据库

+   CRUD 操作

# SQLite 简介

为了保存我们应用程序的数据，我们将需要一个数据库。在 Android 中，可以使用 SQLite 进行离线数据存储。

SQLite 是开箱即用的，这意味着它已经包含在 Android 框架中。

# 好处

SQLite 的好处是它功能强大、快速、可靠，并且有一个庞大的社区在使用它。如果您遇到任何问题，很容易找到解决方案，因为社区中的某人很可能已经解决了这些问题。SQLite 是一个独立的、嵌入式的、功能齐全的、公共领域的 SQL 数据库引擎。

我们将使用 SQLite 来存储所有我们的 Todos 和 Notes。为此，我们将定义我们的数据库、访问它的机制以及数据管理。我们不会直接暴露一个裸的数据库实例，而是会适当地包装它，以便轻松地插入、更新、查询或删除数据。

# 描述我们的数据库

我们将首先通过定义其表和列以及适当的数据类型来描述我们的数据库。我们还将定义简单的模型来表示我们的数据。为此，请创建一个名为`database`的新包：

```kt
     com.journaler.database 
```

然后，创建一个名为`DbModel`的新的 Kotlin 类。`DbModel`类将表示我们应用程序的所有数据库模型的矩阵，并且只包含 ID，因为 ID 是一个必填字段，并且将用作主键。确保您的`DbModel`类看起来像这样：

```kt
    package com.journaler.database 

    abstract class DbModel { 
      abstract var id: Long 
    } 
```

现在，当我们定义了我们的起点后，我们将定义实际包含数据的数据类。在我们现有的名为`model`的包中，创建新的类--`DbEntry`、`Note`和`Todo`。`Note`和`Todo`将扩展`Entry`，而`Entry`又扩展了`DbModel`类。

`Entry`类的代码如下：

```kt
    package com.journaler.model 

    import android.location.Location 
    import com.journaler.database.DbModel 

    abstract class Entry( 
      var title: String, 
      var message: String, 
      var location: Location 
    ) : DbModel() 
    Note class: 
    package com.journaler.model 

    import android.location.Location 

    class Note( 
      title: String, 
      message: String, 
      location: Location 
    ) : Entry( 
        title, 
        message, 
        location 
        ) { 
         override var id = 0L 
        } 
```

您将注意到我们将当前地理位置作为存储在我们的笔记中的信息，以及`title`和笔记`message`内容。我们还重写了 ID。由于新实例化的`note`尚未存储到数据库中，因此其 ID 将为零。存储后，它将更新为从数据库获取的 ID 值。

`Todo`类：

```kt
    package com.journaler.model 

    import android.location.Location 

    class Todo( 
      title: String, 
      message: String, 
      location: Location, 
      var scheduledFor: Long 
    ) : Entry( 
        title, 
        message, 
        location 
    ) { 
    override var id = 0L 
    } 
```

`Todo`类将比`Note`类多一个字段--用于安排`todo`的`timestamp`。

现在，在我们定义了数据模型之后，我们将描述我们的数据库。我们必须定义负责数据库初始化的数据库助手类。数据库助手类必须扩展 Android 的`SQLiteOpenHelper`类。创建`DbHelper`类，并确保它扩展了`SQLiteOpenHelper`类：

```kt
    package com.journaler.database 

    import android.database.sqlite.SQLiteDatabase 
    import android.database.sqlite.SQLiteOpenHelper 
    import android.util.Log 
    import com.journaler.Journaler 

    class DbHelper(val dbName: String, val version: Int) :   
    SQLiteOpenHelper( 
      Journaler.ctx, dbName, null, version 
    ) { 

      companion object { 
        val ID: String = "_id" 
        val TABLE_TODOS = "todos" 
        val TABLE_NOTES = "notes" 
        val COLUMN_TITLE: String = "title" 
        val COLUMN_MESSAGE: String = "message" 
        val COLUMN_SCHEDULED: String = "scheduled" 
        val COLUMN_LOCATION_LATITUDE: String = "latitude" 
        val COLUMN_LOCATION_LONGITUDE: String = "longitude" 
      } 

      private val tag = "DbHelper" 

      private val createTableNotes =  """ 
        CREATE TABLE if not exists $TABLE_NOTES 
           ( 
             $ID integer PRIMARY KEY autoincrement, 
             $COLUMN_TITLE text, 
             $COLUMN_MESSAGE text, 
             $COLUMN_LOCATION_LATITUDE real, 
             $COLUMN_LOCATION_LONGITUDE real 
           ) 
          """ 

      private val createTableTodos =  """ 
        CREATE TABLE if not exists $TABLE_TODOS 
           ( 
              $ID integer PRIMARY KEY autoincrement, 
              $COLUMN_TITLE text, 
              $COLUMN_MESSAGE text, 
              $COLUMN_SCHEDULED integer, 
              $COLUMN_LOCATION_LATITUDE real, 
              $COLUMN_LOCATION_LONGITUDE real 
           ) 
         """ 

       override fun onCreate(db: SQLiteDatabase) { 
        Log.d(tag, "Database [ CREATING ]") 
        db.execSQL(createTableNotes) 
        db.execSQL(createTableTodos) 
        Log.d(tag, "Database [ CREATED ]") 
       } 

      override fun onUpgrade(db: SQLiteDatabase?, oldVersion: Int,
      newVersion: Int) { 
        // Ignore for now. 
      } 

    } 
```

我们的`companion`对象包含了表和列名称的定义。我们还定义了用于创建表的 SQL。最后，SQL 在`onCreate()`方法中执行。在下一节中，我们将进一步进行数据库管理，并最终插入一些数据。

# CRUD 操作

CRUD 操作是用于创建、更新、选择或删除数据的操作。它们是用一个名为`Crud`的接口定义的，并且它将是通用的。在`database`包中创建一个新的接口。确保它涵盖所有 CRUD 操作：

```kt
     interface Crud<T> where T : DbModel { 

       companion object { 
        val BROADCAST_ACTION = "com.journaler.broadcast.crud" 
        val BROADCAST_EXTRAS_KEY_CRUD_OPERATION_RESULT = "crud_result" 
       } 

      /** 
       * Returns the ID of inserted item. 
       */ 
      fun insert(what: T): Long 

      /** 
       * Returns the list of inserted IDs. 
       */ 
      fun insert(what: Collection<T>): List<Long> 

      /** 
      * Returns the number of updated items. 
      */ 
      fun update(what: T): Int 

      /** 
      * Returns the number of updated items. 
      */ 
      fun update(what: Collection<T>): Int 

      /** 
      * Returns the number of deleted items. 
      */ 
      fun delete(what: T): Int 

      /** 
      * Returns the number of deleted items. 
      */ 
      fun delete(what: Collection<T>): Int 

      /** 
      * Returns the list of items. 
      */ 
      fun select(args: Pair<String, String>): List<T> 

      /** 
      * Returns the list of items. 
      */ 
      fun select(args: Collection<Pair<String, String>>): List<T> 

      /** 
      * Returns the list of items. 
      */ 
      fun selectAll(): List<T> 

    } 
```

要执行 CRUD 操作，有两种方法版本。第一个版本是接受*实例集合*的版本，第二个版本是*接受单个项目*的版本。让我们通过创建一个名为`Db`的 Kotlin 对象来创建 CRUD 具体化。创建一个对象使我们的具体化成为一个完美的单例。`Db`对象必须实现`Crud`接口：

```kt
     package com.journaler.database 

     import android.content.ContentValues 
     import android.location.Location 
     import android.util.Log 
     import com.journaler.model.Note 
     import com.journaler.model.Todo 

     object Db { 

      private val tag = "Db" 
      private val version = 1 
      private val name = "students" 

      val NOTE = object : Crud<Note> { 
        // Crud implementations 
      } 

      val TODO = object : Crud<NoteTodo { 
         // Crud implementations 
      } 
    }  
```

# 插入 CRUD 操作

插入操作将新数据添加到数据库中。其实现如下：

```kt
    val NOTE = object : Crud<Note> { 
      ... 
      override fun insert(what: Note): Long { 
        val inserted = insert(listOf(what)) 
        if (!inserted.isEmpty()) return inserted[0] 
        return 0 
      } 

     override fun insert(what: Collection<Note>): List<Long> { 
       val db = DbHelper(name, version).writableDatabase 
       db.beginTransaction() 
       var inserted = 0 
       val items = mutableListOf<Long>() 
       what.forEach { item -> 
         val values = ContentValues() 
         val table = DbHelper.TABLE_NOTES 
         values.put(DbHelper.COLUMN_TITLE, item.title) 
         values.put(DbHelper.COLUMN_MESSAGE, item.message) 
         values.put(DbHelper.COLUMN_LOCATION_LATITUDE,
           item.location.latitude) 
         values.put(DbHelper.COLUMN_LOCATION_LONGITUDE,
           item.location.longitude) 
         val id = db.insert(table, null, values) 
           if (id > 0) { 
             items.add(id) 
             Log.v(tag, "Entry ID assigned [ $id ]") 
               inserted++ 
             } 
           } 
           val success = inserted == what.size 
           if (success) { 
                db.setTransactionSuccessful() 
           } else { 
                items.clear() 
           } 
            db.endTransaction() 
            db.close() 
            return items 
          } 
          ... 
    } 
    ... 
    val TODO = object : Crud<Todo> { 
      ... 
      override fun insert(what: Todo): Long { 
        val inserted = insert(listOf(what)) 
        if (!inserted.isEmpty()) return inserted[0] 
        return 0 
      } 

      override fun insert(what: Collection<Todo>): List<Long> { 
        val db = DbHelper(name, version).writableDatabase 
        db.beginTransaction() 
        var inserted = 0 
        val items = mutableListOf<Long>() 
        what.forEach { item -> 
          val table = DbHelper.TABLE_TODOS 
          val values = ContentValues() 
          values.put(DbHelper.COLUMN_TITLE, item.title) 
          values.put(DbHelper.COLUMN_MESSAGE, item.message) 
          values.put(DbHelper.COLUMN_LOCATION_LATITUDE,
          item.location.latitude) 
          values.put(DbHelper.COLUMN_LOCATION_LONGITUDE,
          item.location.longitude) 
          values.put(DbHelper.COLUMN_SCHEDULED, item.scheduledFor) 
            val id = db.insert(table, null, values) 
            if (id > 0) { 
              item.id = id 
              Log.v(tag, "Entry ID assigned [ $id ]") 
              inserted++ 
            } 
           } 
           val success = inserted == what.size 
           if (success) { 
                db.setTransactionSuccessful() 
           } else { 
               items.clear() 
           } 
           db.endTransaction() 
           db.close() 
           return items 
          } 
         ... 
     } 
     ... 
```

# 更新 CRUD 操作

更新操作将更新我们数据库中的现有数据。其实现如下：

```kt
    val NOTE = object : Crud<Note> { 
       ... 
       override fun update(what: Note) = update(listOf(what)) 

       override fun update(what: Collection<Note>): Int { 
         val db = DbHelper(name, version).writableDatabase 
         db.beginTransaction() 
         var updated = 0 
         what.forEach { item -> 
           val values = ContentValues() 
           val table = DbHelper.TABLE_NOTES 
           values.put(DbHelper.COLUMN_TITLE, item.title) 
           values.put(DbHelper.COLUMN_MESSAGE, item.message) 
           values.put(DbHelper.COLUMN_LOCATION_LATITUDE,
           item.location.latitude) 
           values.put(DbHelper.COLUMN_LOCATION_LONGITUDE,
           item.location.longitude) 
           db.update(table, values, "_id = ?", 
           arrayOf(item.id.toString())) 
                updated++ 
           } 
           val result = updated == what.size 
           if (result) { 
             db.setTransactionSuccessful() 
           } else { 
             updated = 0 
           } 
           db.endTransaction() 
           db.close() 
           return updated 
          } 
          ... 
        } 
        ... 
      val TODO = object : Crud<Todo> { 
        ... 
        override fun update(what: Todo) = update(listOf(what)) 

        override fun update(what: Collection<Todo>): Int { 
          val db = DbHelper(name, version).writableDatabase 
          db.beginTransaction() 
          var updated = 0 
          what.forEach { item -> 
             val table = DbHelper.TABLE_TODOS 
             val values = ContentValues() 
             values.put(DbHelper.COLUMN_TITLE, item.title) 
             values.put(DbHelper.COLUMN_MESSAGE, item.message) 
             values.put(DbHelper.COLUMN_LOCATION_LATITUDE,
             item.location.latitude) 
            values.put(DbHelper.COLUMN_LOCATION_LONGITUDE,
            item.location.longitude) 
            values.put(DbHelper.COLUMN_SCHEDULED, item.scheduledFor) 
            db.update(table, values, "_id = ?",  
            arrayOf(item.id.toString())) 
               updated++ 
            } 
            val result = updated == what.size 
            if (result) { 
              db.setTransactionSuccessful() 
            } else { 
              updated = 0 
            } 
            db.endTransaction() 
            db.close() 
            return updated 
            } 
           ... 
      } 
     ...  
```

# 删除 CRUD 操作

删除操作将从数据库中删除现有数据。其实现如下：

```kt
    val NOTE = object : Crud<Note> { 
      ... 
      override fun delete(what: Note): Int = delete(listOf(what)) 
         override fun delete(what: Collection<Note>): Int { 
         val db = DbHelper(name, version).writableDatabase 
         db.beginTransaction() 
         val ids = StringBuilder() 
         what.forEachIndexed { index, item -> 
         ids.append(item.id.toString()) 
           if (index < what.size - 1) { 
              ids.append(", ") 
           } 
         } 
         val table = DbHelper.TABLE_NOTES 
         val statement = db.compileStatement( 
           "DELETE FROM $table WHERE ${DbHelper.ID} IN ($ids);" 
         ) 
         val count = statement.executeUpdateDelete() 
         val success = count > 0 
         if (success) { 
           db.setTransactionSuccessful() 
           Log.i(tag, "Delete [ SUCCESS ][ $count ][ $statement ]") 
         } else { 
            Log.w(tag, "Delete [ FAILED ][ $statement ]") 
         } 
          db.endTransaction() 
          db.close() 
          return count 
        } 
        ... 
     } 
     ... 
     val TODO = object : Crud<Todo> { 
       ... 
       override fun delete(what: Todo): Int = delete(listOf(what)) 
       override fun delete(what: Collection<Todo>): Int { 
         val db = DbHelper(name, version).writableDatabase 
         db.beginTransaction() 
         val ids = StringBuilder() 
         what.forEachIndexed { index, item -> 
         ids.append(item.id.toString()) 
            if (index < what.size - 1) { 
                ids.append(", ") 
            } 
        } 
        val table = DbHelper.TABLE_TODOS 
        val statement = db.compileStatement( 
          "DELETE FROM $table WHERE ${DbHelper.ID} IN ($ids);" 
        ) 
        val count = statement.executeUpdateDelete() 
        val success = count > 0 
        if (success) { 
           db.setTransactionSuccessful() 
           Log.i(tag, "Delete [ SUCCESS ][ $count ][ $statement ]") 
        } else { 
           Log.w(tag, "Delete [ FAILED ][ $statement ]") 
        } 
         db.endTransaction() 
         db.close() 
         return count 
        } 
        ... 
    } 
    ...  
```

# 选择 CRUD 操作

选择操作将从数据库中读取并返回数据。其实现如下：

```kt
     val NOTE = object : Crud<Note> { 
        ... 
        override fun select( 
            args: Pair<String, String> 
        ): List<Note> = select(listOf(args)) 

        override fun select(args: Collection<Pair<String, String>>):
        List<Note> { 
          val db = DbHelper(name, version).writableDatabase 
          val selection = StringBuilder() 
          val selectionArgs = mutableListOf<String>() 
          args.forEach { arg -> 
              selection.append("${arg.first} == ?") 
              selectionArgs.add(arg.second) 
          } 
          val result = mutableListOf<Note>() 
          val cursor = db.query( 
              true, 
              DbHelper.TABLE_NOTES, 
              null, 
              selection.toString(), 
              selectionArgs.toTypedArray(), 
              null, null, null, null 
          ) 
          while (cursor.moveToNext()) { 
          val id = cursor.getLong(cursor.getColumnIndexOrThrow
          (DbHelper.ID)) 
          val titleIdx = cursor.getColumnIndexOrThrow
          (DbHelper.COLUMN_TITLE) 
          val title = cursor.getString(titleIdx) 
          val messageIdx = cursor.getColumnIndexOrThrow
          (DbHelper.COLUMN_MESSAGE) 
          val message = cursor.getString(messageIdx) 
          val latitudeIdx = cursor.getColumnIndexOrThrow( 
             DbHelper.COLUMN_LOCATION_LATITUDE 
          ) 
          val latitude = cursor.getDouble(latitudeIdx) 
          val longitudeIdx = cursor.getColumnIndexOrThrow( 
             DbHelper.COLUMN_LOCATION_LONGITUDE 
          ) 
          val longitude = cursor.getDouble(longitudeIdx) 
          val location = Location("") 
          location.latitude = latitude 
          location.longitude = longitude 
          val note = Note(title, message, location) 
          note.id = id 
          result.add(note) 
        } 
          cursor.close() 
          return result 
       } 

       override fun selectAll(): List<Note> { 
         val db = DbHelper(name, version).writableDatabase 
         val result = mutableListOf<Note>() 
         val cursor = db.query( 
            true, 
            DbHelper.TABLE_NOTES, 
            null, null, null, null, null, null, null 
         ) 
         while (cursor.moveToNext()) { 
                val id = cursor.getLong(cursor.getColumnIndexOrThrow
               (DbHelper.ID)) 
                val titleIdx = cursor.getColumnIndexOrThrow
                (DbHelper.COLUMN_TITLE) 
                val title = cursor.getString(titleIdx) 
                val messageIdx = cursor.getColumnIndexOrThrow
                (DbHelper.COLUMN_MESSAGE) 
                val message = cursor.getString(messageIdx) 
                val latitudeIdx = cursor.getColumnIndexOrThrow( 
                  DbHelper.COLUMN_LOCATION_LATITUDE 
                ) 
                val latitude = cursor.getDouble(latitudeIdx) 
                val longitudeIdx = cursor.getColumnIndexOrThrow( 
                   DbHelper.COLUMN_LOCATION_LONGITUDE 
                ) 
                val longitude = cursor.getDouble(longitudeIdx) 
                val location = Location("") 
                location.latitude = latitude 
                location.longitude = longitude 
                val note = Note(title, message, location) 
                note.id = id 
                result.add(note) 
              } 
             cursor.close() 
             return result 
            } 
            ... 
          } 
          ... 
       val TODO = object : Crud<Todo> { 
        ... 
        override fun select(args: Pair<String, String>): List<Todo> =
        select(listOf(args)) 

        override fun select(args: Collection<Pair<String, String>>): 
        List<Todo> { 
          val db = DbHelper(name, version).writableDatabase 
          val selection = StringBuilder() 
          val selectionArgs = mutableListOf<String>() 
          args.forEach { arg -> 
             selection.append("${arg.first} == ?") 
             selectionArgs.add(arg.second) 
          } 
          val result = mutableListOf<Todo>() 
          val cursor = db.query( 
             true, 
             DbHelper.TABLE_NOTES, 
             null, 
             selection.toString(), 
             selectionArgs.toTypedArray(), 
             null, null, null, null 
            ) 
            while (cursor.moveToNext()) { 
                val id = cursor.getLong(cursor.getColumnIndexOrThrow
                (DbHelper.ID)) 
                val titleIdx = cursor.getColumnIndexOrThrow
                (DbHelper.COLUMN_TITLE) 
                val title = cursor.getString(titleIdx) 
                val messageIdx = cursor.getColumnIndexOrThrow
                (DbHelper.COLUMN_MESSAGE) 
                val message = cursor.getString(messageIdx) 
                val latitudeIdx = cursor.getColumnIndexOrThrow( 
                    DbHelper.COLUMN_LOCATION_LATITUDE 
                ) 
                val latitude = cursor.getDouble(latitudeIdx) 
                val longitudeIdx = cursor.getColumnIndexOrThrow( 
                    DbHelper.COLUMN_LOCATION_LONGITUDE 
                ) 
                val longitude = cursor.getDouble(longitudeIdx) 
                val location = Location("") 
                val scheduledForIdx = cursor.getColumnIndexOrThrow( 
                    DbHelper.COLUMN_SCHEDULED 
                ) 
                val scheduledFor = cursor.getLong(scheduledForIdx) 
                location.latitude = latitude 
                location.longitude = longitude 
                val todo = Todo(title, message, location, scheduledFor) 
                todo.id = id 
                result.add(todo) 
               } 
              cursor.close() 
              return result 
            } 

            override fun selectAll(): List<Todo> { 
            val db = DbHelper(name, version).writableDatabase 
            val result = mutableListOf<Todo>() 
            val cursor = db.query( 
              true, 
              DbHelper.TABLE_NOTES, 
              null, null, null, null, null, null, null 
            ) 
            while (cursor.moveToNext()) { 
                val id = cursor.getLong(cursor.getColumnIndexOrThrow
                (DbHelper.ID)) 
                val titleIdx = cursor.getColumnIndexOrThrow
                (DbHelper.COLUMN_TITLE) 
                val title = cursor.getString(titleIdx) 
                val messageIdx = cursor.getColumnIndexOrThrow
                (DbHelper.COLUMN_MESSAGE) 
                val message = cursor.getString(messageIdx) 
                val latitudeIdx = cursor.getColumnIndexOrThrow( 
                    DbHelper.COLUMN_LOCATION_LATITUDE 
                ) 
                val latitude = cursor.getDouble(latitudeIdx) 
                val longitudeIdx = cursor.getColumnIndexOrThrow( 
                    DbHelper.COLUMN_LOCATION_LONGITUDE 
                ) 
                val longitude = cursor.getDouble(longitudeIdx) 
                val location = Location("") 
                val scheduledForIdx = cursor.getColumnIndexOrThrow( 
                    DbHelper.COLUMN_SCHEDULED 
                ) 
                val scheduledFor = cursor.getLong(scheduledForIdx) 
                location.latitude = latitude 
                location.longitude = longitude 
                val todo = Todo(title, message, location, scheduledFor) 
                todo.id = id 
                result.add(todo) 
              } 
              cursor.close() 
               return result 
             } 
             ... 
        } 
        ... 
```

每个 CRUD 操作都将使用我们的`DbHelper`类获取数据库实例。我们不会直接暴露它，而是通过我们的 CRUD 机制来利用它。每次操作后，数据库都将被关闭。我们只能通过访问`writableDatabase`来获取可读数据库或者像我们的情况一样获取`WritableDatabase`实例。每个 CRUD 操作都作为一个 SQL 事务执行。这意味着我们将通过在数据库实例上调用`beginTransaction()`来开始它。通过调用`endTransaction()`来完成事务。如果我们在之前没有调用`setTransactionSuccessful()`，则不会应用任何更改。正如我们已经提到的，每个 CRUD 操作都有两个版本--一个包含主要实现，另一个只是将实例传递给另一个。要执行对数据库的插入，重要的是要注意我们将在数据库实例上使用`insert()`方法，该方法接受我们要插入的表名和代表数据的内容值（`ContentValues`类）。`update`和`delete`操作类似。我们使用`update()`和`delete()`方法。在我们的情况下，对于数据删除，我们使用了包含删除 SQL 查询的`compileStatement()`。

我们在这里提供的代码有点复杂。我们直接指向了与数据库相关的事项。所以，请耐心阅读代码，慢慢来，花时间来研究它。我们鼓励您利用我们已经提到的 Android 数据库类，以您自己的方式创建自己的数据库管理类。

# 将事物联系在一起

我们还有一步！那就是实际使用我们的数据库类并执行 CRUD 操作。我们将扩展应用程序以创建笔记，并专注于插入。

在我们向数据库中插入任何内容之前，我们必须提供一种机制来获取当前用户位置，因为这对于`notes`和`todos`都是必需的。创建一个名为`LocationProvider`的新类，并将其定位在`location`包中，如下所示：

```kt
     object LocationProvider { 
       private val tag = "Location provider" 
       private val listeners =   CopyOnWriteArrayList
       <WeakReference<LocationListener>>() 

       private val locationListener = object : LocationListener { 
       ... 
       } 

      fun subscribe(subscriber: LocationListener): Boolean { 
        val result = doSubscribe(subscriber) 
        turnOnLocationListening() 
        return result 
      } 

      fun unsubscribe(subscriber: LocationListener): Boolean { 
        val result = doUnsubscribe(subscriber) 
        if (listeners.isEmpty()) { 
            turnOffLocationListening() 
        } 
        return result 
      } 

      private fun turnOnLocationListening() { 
      ... 
      } 

      private fun turnOffLocationListening() { 
      ... 
      } 

      private fun doSubscribe(listener: LocationListener): Boolean { 
      ... 
      } 

      private fun doUnsubscribe(listener: LocationListener): Boolean { 
       ... 
      } 
    } 
```

我们公开了`LocationProvider`对象的主要结构。让我们来看看其余的实现：

`locationListener`实例代码如下：

```kt
     private val locationListener = object : LocationListener { 
        override fun onLocationChanged(location: Location) { 
            Log.i( 
                    tag, 
                    String.format( 
                            Locale.ENGLISH, 
                            "Location [ lat: %s ][ long: %s ]",
                            location.latitude, location.longitude 
                    ) 
            ) 
            val iterator = listeners.iterator() 
            while (iterator.hasNext()) { 
                val reference = iterator.next() 
                val listener = reference.get() 
                listener?.onLocationChanged(location) 
            } 
         } 

        override fun onStatusChanged(provider: String, status: Int,
        extras: Bundle) { 
            Log.d( 
                    tag, 
                    String.format(Locale.ENGLISH, "Status changed [ %s
                    ][ %d ]", provider, status) 
            ) 
            val iterator = listeners.iterator() 
            while (iterator.hasNext()) { 
                val reference = iterator.next() 
                val listener = reference.get() 
                listener?.onStatusChanged(provider, status, extras) 
            } 
        } 

        override fun onProviderEnabled(provider: String) { 
            Log.i(tag, String.format("Provider [ %s ][ ENABLED ]",
            provider)) 
            val iterator = listeners.iterator() 
            while (iterator.hasNext()) { 
                val reference = iterator.next() 
                val listener = reference.get() 
                listener?.onProviderEnabled(provider) 
            } 
        } 

        override fun onProviderDisabled(provider: String) { 
            Log.i(tag, String.format("Provider [ %s ][ ENABLED ]",
            provider)) 
            val iterator = listeners.iterator() 
            while (iterator.hasNext()) { 
                val reference = iterator.next() 
                val listener = reference.get() 
                listener?.onProviderDisabled(provider) 
            } 
          } 
         } 
```

`LocationListener`是 Android 的接口，其目的是在`location`事件上执行。我们创建了我们的具体化，基本上会通知所有订阅方有关这些事件的信息。对我们来说最重要的是`onLocationChanged()`：

```kt
    turnOnLocationListening(): 

    private fun turnOnLocationListening() { 
       Log.v(tag, "We are about to turn on location listening.") 
       val ctx = Journaler.ctx 
       if (ctx != null) { 
            Log.v(tag, "We are about to check location permissions.") 

            val permissionsOk = 
            ActivityCompat.checkSelfPermission(ctx,
            Manifest.permission.ACCESS_FINE_LOCATION) ==  
            PackageManager.PERMISSION_GRANTED  
            &&  
            ActivityCompat.checkSelfPermission(ctx, 
            Manifest.permission.ACCESS_COARSE_LOCATION) ==
            PackageManager.PERMISSION_GRANTED 

            if (!permissionsOk) { 
                throw IllegalStateException( 
                "Permissions required [ ACCESS_FINE_LOCATION ]
                 [ ACCESS_COARSE_LOCATION ]" 
                ) 
            } 
            Log.v(tag, "Location permissions are ok. 
            We are about to request location changes.") 
            val locationManager =
            ctx.getSystemService(Context.LOCATION_SERVICE)
            as LocationManager 

            val criteria = Criteria() 
            criteria.accuracy = Criteria.ACCURACY_FINE 
            criteria.powerRequirement = Criteria.POWER_HIGH 
            criteria.isAltitudeRequired = false 
            criteria.isBearingRequired = false 
            criteria.isSpeedRequired = false 
            criteria.isCostAllowed = true 

            locationManager.requestLocationUpdates( 
                    1000, 1F, criteria, locationListener, 
                    Looper.getMainLooper() 
            ) 
            } else { 
             Log.e(tag, "No application context available.") 
          } 
        } 
```

要打开位置监听，我们必须检查权限是否得到了正确的满足。如果是这样，那么我们将获取 Android 的`LocationManager`并为位置更新定义`Criteria`。我们将我们的标准定义为非常精确和准确。最后，我们通过传递以下参数来请求位置更新：

+   `long minTime`

+   `float minDistance`

+   `Criteria criteria`

+   `LocationListener listener`

+   `Looper looper`

正如您所看到的，我们传递了我们的`LocationListener`具体化，它将通知所有订阅的第三方有关`location`事件的信息：

```kt
     turnOffLocationListening():private fun turnOffLocationListening() 
     { 
       Log.v(tag, "We are about to turn off location listening.") 
       val ctx = Journaler.ctx 
       if (ctx != null) { 
         val locationManager =  
         ctx.getSystemService(Context.LOCATION_SERVICE)
         as LocationManager 

         locationManager.removeUpdates(locationListener) 
        } else { 
            Log.e(tag, "No application context available.") 
        } 
     } 
```

+   我们通过简单地移除我们的监听器`instance.doSubscribe()`来停止监听位置。

```kt
      private fun doSubscribe(listener: LocationListener): Boolean { 
        val iterator = listeners.iterator() 
        while (iterator.hasNext()) { 
          val reference = iterator.next() 
          val refListener = reference.get() 
          if (refListener != null && refListener === listener) { 
                Log.v(tag, "Already subscribed: " + listener) 
                return false 
            } 
         } 
         listeners.add(WeakReference(listener)) 
         Log.v(tag, "Subscribed, subscribers count: " + listeners.size) 
         return true 
      }  
```

+   `doUnsubscribe()`方法代码如下：

```kt
      private fun doUnsubscribe(listener: LocationListener): Boolean { 
        var result = true 
        val iterator = listeners.iterator() 
        while (iterator.hasNext()) { 
            val reference = iterator.next() 
            val refListener = reference.get() 
            if (refListener != null && refListener === listener) { 
                val success = listeners.remove(reference) 
                if (!success) { 
                    Log.w(tag, "Couldn't un subscribe, subscribers
                    count: " + listeners.size) 
                } else { 
                    Log.v(tag, "Un subscribed, subscribers count: " +
                    listeners.size) 
                } 
                if (result) { 
                    result = success 
                } 
               } 
             } 
            return result 
        } 
```

这两种方法负责订阅和取消订阅位置更新给感兴趣的第三方。

我们已经拥有了所需的一切。打开`NoteActivity`类并扩展如下：

```kt
     class NoteActivity : ItemActivity() { 
       private var note: Note? = null 
       override val tag = "Note activity" 
       private var location: Location? = null 
       override fun getLayout() = R.layout.activity_note 

      private val textWatcher = object : TextWatcher { 
        override fun afterTextChanged(p0: Editable?) { 
            updateNote() 
        } 

        override fun beforeTextChanged(p0: CharSequence?, p1: Int, p2:
        Int, p3: Int) {} 
        override fun onTextChanged(p0: CharSequence?, p1: Int, p2:
        Int, p3: Int) {} 
      } 

      private val locationListener = object : LocationListener { 
        override fun onLocationChanged(p0: Location?) { 
            p0?.let { 
                LocationProvider.unsubscribe(this) 
                location = p0 
                val title = getNoteTitle() 
                val content = getNoteContent() 
                note = Note(title, content, p0) 
                val task = object : AsyncTask<Note, Void, Boolean>() { 
                    override fun doInBackground(vararg params: Note?):
                    Boolean { 
                        if (!params.isEmpty()) { 
                            val param = params[0] 
                            param?.let { 
                                return Db.NOTE.insert(param) > 0 
                            } 
                        } 
                        return false 
                    } 

                    override fun onPostExecute(result: Boolean?) { 
                        result?.let { 
                            if (result) { 
                                Log.i(tag, "Note inserted.") 
                            } else { 
                                Log.e(tag, "Note not inserted.") 
                            } 
                        } 
                     } 
                  } 
                task.execute(note) 
              } 
          } 

         override fun onStatusChanged(p0: String?, p1: Int, p2:
         Bundle?) {} 
         override fun onProviderEnabled(p0: String?) {} 
         override fun onProviderDisabled(p0: String?) {} 
        } 

        override fun onCreate(savedInstanceState: Bundle?) { 
          super.onCreate(savedInstanceState) 
          note_title.addTextChangedListener(textWatcher) 
          note_content.addTextChangedListener(textWatcher) 
        } 

       private fun updateNote() { 
         if (note == null) { 
          if (!TextUtils.isEmpty(getNoteTitle()) &&
          !TextUtils.isEmpty(getNoteContent())) { 
             LocationProvider.subscribe(locationListener) 
          } 
         } else { 
            note?.title = getNoteTitle() 
            note?.message = getNoteContent() 
            val task = object : AsyncTask<Note, Void, Boolean>() { 
                override fun doInBackground(vararg params: Note?):
            Boolean { 
              if (!params.isEmpty()) { 
                 val param = params[0] 
                 param?.let { 
                   return Db.NOTE.update(param) > 0 
                  } 
                } 
                  return false 
              } 

              override fun onPostExecute(result: Boolean?) { 
                result?.let { 
                   if (result) { 
                       Log.i(tag, "Note updated.") 
                   } else { 
                       Log.e(tag, "Note not updated.") 
                   } 
                 } 
               } 
            } 
            task.execute(note) 
          } 
       } 

       private fun getNoteContent(): String { 
         return note_content.text.toString() 
       } 

       private fun getNoteTitle(): String { 
         return note_title.text.toString() 
       } 

     } 
```

我们在这里做了什么？让我们从上到下解释一切！我们添加了两个字段——一个包含我们正在编辑的当前`Note`实例，另一个包含当前用户位置信息。然后，我们定义了一个`TextWatcher`实例。`TextWatcher`是一个监听器，我们将分配给我们的`EditText`视图，每次更改时，适当的更新方法将被触发。该方法将创建一个新的`note`类，并将其持久化到数据库中（如果不存在），或者如果存在，则执行数据更新。

由于在没有位置数据可用之前，我们不会插入笔记，因此我们定义了我们的`locationListener`将接收到的位置放入位置字段中，并取消订阅自身。然后，我们将获取`note`标题和其主要内容的当前值，并创建一个新的`note`实例。由于数据库操作可能需要一些时间，我们将以异步方式执行它们。为此，我们将使用`AsyncTask`类。`AsyncTask`类是 Android 的类，旨在用于大多数异步操作。该类定义了输入类型、进度类型和结果类型。在我们的情况下，输入类型是`Note`。我们没有进度类型，但我们有一个结果类型`Boolean`，即操作是否成功。

主要工作是在`doInBackground()`具体化中完成的，而结果在`onPostExecute()`中处理。正如你所看到的，我们正在使用我们最近为数据库管理定义的类在后台执行插入操作。

如果你继续查看，我们接下来要做的事情是将`textWatcher`分配给`onCreate()`方法中的`EditText`视图。然后，我们定义了我们最重要的方法——`updateNote()`。它将更新现有的笔记，如果不存在，则插入一个新的笔记。同样，我们使用`AsyncTask`在后台执行操作。

构建你的应用程序并运行它。尝试插入`note`。观察你的 Logcat。你会注意到与数据库相关的日志，如下所示：

```kt
    I/Note activity: Note inserted. 
    I/Note activity: Note updated. 
    I/Note activity: Note updated. 
    I/Note activity: Note updated. 
```

如果你能看到这些日志，那么你已经成功在 Android 中实现了你的第一个数据库。我们鼓励你扩展代码以支持其他 CRUD 操作。确保`NoteActivity`支持`select`和`delete`操作。

# 总结

在本章中，我们演示了如何在 Android 中持久化复杂数据。数据库是每个应用程序的核心，所以 Journaler 也不例外。我们涵盖了在 SQLite 数据库上执行的所有 CRUD 操作，并为每个操作提供了适当的实现。在我们的下一章中，我们将演示另一种持久化机制，用于较不复杂的数据。我们将处理 Android 共享首选项，并将使用它们来保存我们应用程序的简单小数据。


# 第八章：Android 偏好设置

在上一章中，我们处理了存储在 SQLite 数据库中的复杂数据。这一次，我们将处理一种更简单的数据形式。我们将涵盖一个特定的用例，以演示 Android 共享偏好设置的使用。

假设我们想要记住我们的`ViewPager`类的最后一页位置，并在每次启动应用程序时打开它。我们将使用共享偏好设置来记住它，并在每次视图页面位置更改时持久化该信息，并在需要时检索它。

在这个相当简短的章节中，我们将涵盖以下主题：

+   Android 的偏好设置是什么，你如何使用它们？

+   定义自己的偏好设置管理器

# Android 的偏好设置是什么？

我们应用程序的偏好设置是由 Android 的共享偏好设置机制持久化和检索的。共享偏好设置本身代表 Android 及其 API 访问和修改的 XML 数据。Android 处理有关检索和保存偏好设置的所有工作。它还提供了这些偏好设置为私有的机制，隐藏在公共访问之外。Android SDK 具有一套用于偏好设置管理的优秀类。还有可用的抽象，因此您不仅限于默认的 XML，而可以创建自己的持久化层。

# 你如何使用它们？

要使用共享偏好设置，您必须从当前上下文获取`SharedPreferences`实例：

```kt
    val prefs = ctx.getSharedPreferences(key, mode) 
```

在这里，`key`表示将命名此共享偏好设置实例的`String`。系统中的 XML 文件也将具有该名称。这些是可以从`Context 类`获得的模式（操作模式）：

+   `MODE_PRIVATE`：这是默认模式，创建的文件只能被我们的调用应用程序访问

+   `MODE_WORLD_READABLE`：这已被弃用

+   `MODE_WORLD_WRITEABLE`：这已被弃用

然后，我们可以存储值或按以下方式检索它们：

```kt
    val value = prefs.getString("key", "default value")  
```

所有常见数据类型都有类似的`getter`方法。

# 编辑（存储）偏好设置

我们将通过提供偏好设置编辑的示例来开始本节：

```kt
    preferences.edit().putString("key", "balue").commit() 
```

`commit()`方法立即执行操作，而`apply()`方法在后台执行操作。

如果使用`commit()`方法，永远不要从应用程序的主线程获取或操作共享偏好设置。

确保所有写入和读取都在后台执行。您可以使用`AsyncTask`来实现这一目的，或者使用`apply()`而不是`commit()`。

# 删除偏好设置

删除偏好设置，有一个`remove`方法可用，如下所示：

```kt
    prefs.edit().remove("key").commit() 
```

不要通过用空数据覆盖它们来删除您的偏好设置。例如，用 null 覆盖整数或用空字符串覆盖字符串。

# 定义自己的偏好设置管理器

为了实现本章开头的任务，我们将创建一个适当的机制来获取共享偏好设置。

创建一个名为`preferences`的新包。我们将把所有与`preferences`相关的代码放在该包中。对于共享偏好设置管理，我们将需要以下三个类：

+   `PreferencesProviderAbstract`：这是提供对 SharedPreferences 的访问的基本抽象

+   `PreferencesProvider`：这是`PreferencesProviderAbstract`的实现

+   `PreferencesConfiguration`：这个类负责描述我们尝试实例化的偏好设置

使用这种方法的好处是在我们的应用程序中统一访问共享偏好设置的方法。

让我们定义每个类如下：

+   `PreferencesProviderAbstract`类代码如下：

```kt
         package com.journaler.perferences 

         import android.content.Context 
         import android.content.SharedPreferences 

         abstract class PreferencesProviderAbstract { 
           abstract fun obtain(configuration: PreferencesConfiguration,
           ctx: Context): SharedPreferences 
         } 
```

+   `PreferencesConfiguration`类代码如下：

```kt
         package com.journaler.perferences 
         data class PreferencesConfiguration
         (val key: String, val mode: Int) 
```

+   `PreferencesProvider`类代码如下：

```kt
        package com.journaler.perferences 

        import android.content.Context 
        import android.content.SharedPreferences 

        class PreferencesProvider : PreferencesProviderAbstract() { 
          override fun obtain(configuration: PreferencesConfiguration,
          ctx: Context): SharedPreferences { 
            return ctx.getSharedPreferences(configuration.key,
            configuration.mode) 
          } 
        } 
```

正如你所看到的，我们创建了一个简单的机制来获取共享偏好设置。我们将加以整合。打开`MainActivity`类，并根据以下代码进行扩展：

```kt
     class MainActivity : BaseActivity() { 
       ... 
       private val keyPagePosition = "keyPagePosition" 
       ... 

       override fun onCreate(savedInstanceState: Bundle?) { 
         super.onCreate(savedInstanceState) 

         val provider = PreferencesProvider() 
         val config = PreferencesConfiguration("journaler_prefs",
         Context.MODE_PRIVATE) 
         val preferences = provider.obtain(config, this) 

         pager.adapter = ViewPagerAdapter(supportFragmentManager) 
         pager.addOnPageChangeListener(object :
         ViewPager.OnPageChangeListener { 
            override fun onPageScrollStateChanged(state: Int) { 
                // Ignore 
         } 

         override fun onPageScrolled(position: Int, positionOffset:
         Float, positionOffsetPixels: Int) { 
                // Ignore 
         } 

         override fun onPageSelected(position: Int) { 
           Log.v(tag, "Page [ $position ]") 
           preferences.edit().putInt(keyPagePosition, position).apply() 
         } 
       }) 

       val pagerPosition = preferences.getInt(keyPagePosition, 0) 
       pager.setCurrentItem(pagerPosition, true) 
       ... 
      } 
      ... 
     } 
```

我们创建了`preferences`实例，用于持久化和读取视图页面位置。构建并运行您的应用程序；滑动到其中一个页面，然后关闭您的应用程序并再次运行。如果您查看 Logcat，您将看到类似以下内容的信息（通过`Page`进行过滤）：

```kt
     V/Main activity: Page [ 1 ] 
     V/Main activity: Page [ 2 ] 
     V/Main activity: Page [ 3 ] 
     After we restarted the application: 
     V/Main activity: Page [ 3 ] 
     V/Main activity: Page [ 2 ] 
     V/Main activity: Page [ 1 ] 
     V/Main activity: Page [ 0 ] 
```

我们在关闭后再次打开应用程序，并滑动回索引为`0`的页面。

# 总结

在本章中，您学习了如何使用 Android 共享偏好机制来持久化应用程序偏好设置。正如您所看到的，创建应用程序偏好设置并在应用程序中使用它们非常容易。在下一章中，我们将专注于 Android 中的并发性。我们将学习 Android 提供的机制，并举例说明如何使用它们。


# 第九章：Android 中的并发

在本章中，我们将解释 Android 中的并发。我们将给出例子和建议，并将并发应用到我们的 Journaler 应用程序中。我们已经通过演示`AsyncTask`类的使用来介绍了一些基础知识，但现在我们将深入探讨。

在本章中，我们将涵盖以下主题：

+   处理程序和线程

+   `AsyncTask`

+   Android Looper

+   延迟执行

# 介绍 Android 并发

我们的应用程序的默认执行是在主应用程序线程上执行的。这个执行必须是高效的！如果发生某些操作花费太长时间，那么我们会得到 ANR--Android 应用程序无响应的消息。为了避免 ANR，我们在后台运行我们的代码。Android 提供了机制，让我们可以高效地这样做。异步运行操作不仅可以提供良好的性能，还可以提供良好的用户体验。

# 主线程

所有用户界面更新都是从一个线程执行的。这就是主线程。所有事件都被收集在一个队列中，并由`Looper`类实例处理。

以下图片解释了涉及的类之间的关系：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/1b186908-463f-4a05-9454-c76fdb4bdde7.png)

重要的是要注意，主线程更新是你看到的所有 UI。但它也可以从其他线程执行。直接从其他线程执行这些操作会导致异常，你的应用程序可能会崩溃。为了避免这种情况，通过从当前活动上下文调用`runOnUiThread()`方法在主线程上执行所有与线程相关的代码。

# 处理程序和线程

在 Android 中，可以通过使用线程来执行线程。不建议只是随意启动线程而没有任何控制。因此，为此目的，可以使用`ThreadPools`和`Executor`类。

为了演示这一点，我们将更新我们的应用程序。创建一个名为`execution`的新包，并在其中创建一个名为`TaskExecutor`的类。确保它看起来像这样：

```kt
     package com.journaler.execution 

     import java.util.concurrent.BlockingQueue 
     import java.util.concurrent.LinkedBlockingQueue 
     import java.util.concurrent.ThreadPoolExecutor 
     import java.util.concurrent.TimeUnit 

     class TaskExecutor private constructor( 
        corePoolSize: Int, 
        maximumPoolSize: Int, 
        workQueue: BlockingQueue<Runnable>? 

    ) : ThreadPoolExecutor( 
        corePoolSize, 
        maximumPoolSize, 
        0L, 
        TimeUnit.MILLISECONDS, 
        workQueue 
    ) { 

    companion object { 
        fun getInstance(capacity: Int): TaskExecutor { 
            return TaskExecutor( 
                    capacity, 
                    capacity * 2, 
                    LinkedBlockingQueue<Runnable>() 
            ) 
        } 
    } }
```

我们扩展了`ThreadPoolExecutor`类和`companion`对象，并为执行器实例化添加了成员方法。让我们将其应用到我们现有的代码中。我们将从我们使用的`AsyncTask`类切换到`TaskExecutor`。打开`NoteActivity`类并按照以下方式更新它：

```kt
     class NoteActivity : ItemActivity() { 
       ... 
       private val executor = TaskExecutor.getInstance(1) 
       ... 
       private val locationListener = object : LocationListener { 
         override fun onLocationChanged(p0: Location?) { 
            p0?.let { 
                LocationProvider.unsubscribe(this) 
                location = p0 
                val title = getNoteTitle() 
                val content = getNoteContent() 
                note = Note(title, content, p0) 
                executor.execute { 
                  val param = note 
                  var result = false 
                  param?.let { 
                      result = Db.insert(param) 
                  } 
                  if (result) { 
                      Log.i(tag, "Note inserted.") 
                  } else { 
                      Log.e(tag, "Note not inserted.") 
                  } 
               } 

            } 
         } 

        override fun onStatusChanged(p0: String?, p1: Int, p2: Bundle?)
        {} 
        override fun onProviderEnabled(p0: String?) {} 
        override fun onProviderDisabled(p0: String?) {} 
      } 
         ... 
      private fun updateNote() { 
       if (note == null) { 
         if (!TextUtils.isEmpty(getNoteTitle()) &&
         !TextUtils.isEmpty(getNoteContent())) { 
            LocationProvider.subscribe(locationListener) 
          } 
        } else { 
           note?.title = getNoteTitle() 
           note?.message = getNoteContent() 
           executor.execute { 
             val param = note 
             var result = false 
             param?.let { 
                result = Db.update(param) 
             } 
             if (result) { 
                Log.i(tag, "Note updated.") 
             } else { 
                Log.e(tag, "Note not updated.") 
             } 
           } 
        } 
       } 
  ... }
```

如你所见，我们用执行器替换了`AsyncTask`。我们的执行器一次只处理一个线程。

除了标准的线程方法，Android 还提供了处理程序作为开发人员的选择之一。处理程序不是线程的替代品，而是一种补充！处理程序实例会在其父线程中注册自己。它代表了向特定线程发送数据的机制。我们可以发送`Message`或`Runnable`类的实例。让我们通过一个例子来说明它的用法。我们将使用指示器更新笔记屏幕，如果一切都执行正确，指示器将是绿色。如果数据库持久化失败，它将是红色。它的默认颜色将是灰色。打开`activity_note.xml`文件并扩展它以包含指示器。指示器将是普通视图，如下所示：

```kt
     <?xml version="1.0" encoding="utf-8"?> 
     <ScrollView xmlns:android=
      "http://schemas.android.com/apk/res/android" 
     android:layout_width="match_parent" 
     android:layout_height="match_parent" 
     android:fillViewport="true"> 

     <LinearLayout 
        android:layout_width="match_parent" 
        android:layout_height="wrap_content" 
        android:background="@color/black_transparent_40" 
        android:orientation="vertical"> 

        ... 

        <RelativeLayout 
            android:layout_width="match_parent" 
            android:layout_height="wrap_content"> 

            <View 
                android:id="@+id/indicator" 
                android:layout_width="40dp" 
                android:layout_height="40dp" 
                android:layout_alignParentEnd="true" 
                android:layout_centerVertical="true" 
                android:layout_margin="10dp" 
                android:background="@android:color/darker_gray" /> 

            <EditText 
                android:id="@+id/note_title" 
                style="@style/edit_text_transparent" 
                android:layout_width="match_parent" 
                android:layout_height="wrap_content" 
                android:hint="@string/title" 
                android:padding="@dimen/form_padding" /> 

        </RelativeLayout>         
         ...      
      </LinearLayout> 

    </ScrollView> 
```

现在，当我们添加指示器时，它将根据数据库插入结果改变颜色。像这样更新你的`NoteActivity`类源代码：

```kt
     class NoteActivity : ItemActivity() { 
      ... 
      private var handler: Handler? = null 
      .... 
      override fun onCreate(savedInstanceState: Bundle?) { 
        super.onCreate(savedInstanceState) 
        handler = Handler(Looper.getMainLooper()) 
        ... 
      } 
      ... 
      private val locationListener = object : LocationListener { 
        override fun onLocationChanged(p0: Location?) { 
            p0?.let { 
                ... 
                executor.execute { 
                    ... 
                    handler?.post { 
                        var color = R.color.vermilion 
                        if (result) { 
                            color = R.color.green 
                        } 
                        indicator.setBackgroundColor( 
                                ContextCompat.getColor( 
                                        this@NoteActivity, 
                                        color 
                                ) 
                        ) 
                    } 
                } 
            } 
        } 

        override fun onStatusChanged(p0: String?, p1: Int, p2: Bundle?)
        {} 
        override fun onProviderEnabled(p0: String?) {} 
        override fun onProviderDisabled(p0: String?) {} 
      } 
     ... 
     private fun updateNote() { 
        if (note == null) { 
            ... 
        } else { 
            ... 
            executor.execute { 
                ... 
                handler?.post { 
                    var color = R.color.vermilion 
                    if (result) { 
                        color = R.color.green 
                    } 
                    indicator.setBackgroundColor
                    (ContextCompat.getColor( 
                        this@NoteActivity, 
                        color 
                    )) 
                 } 
               } 
            } 
        } }
```

构建你的应用程序并运行它。创建一个新的笔记。你会注意到，在输入标题和消息内容后，指示器的颜色变成了绿色。

我们将进行一些更改，并对`Message`类实例执行相同的操作。根据这个示例更新你的代码：

```kt
     class NoteActivity : ItemActivity() { 
      ... 
      override fun onCreate(savedInstanceState: Bundle?) { 
        super.onCreate(savedInstanceState) 
        handler = object : Handler(Looper.getMainLooper()) { 
            override fun handleMessage(msg: Message?) { 
                msg?.let { 
                    var color = R.color.vermilion 
                    if (msg.arg1 > 0) { 
                        color = R.color.green 
                    } 
                    indicator.setBackgroundColor
                    (ContextCompat.getColor( 
                       this@NoteActivity, 
                       color 
                    )) 
                  } 
                 super.handleMessage(msg) 
               } 
             } 
            ... 
          } 
        ... 
        private val locationListener = object : LocationListener { 
        override fun onLocationChanged(p0: Location?) { 
            p0?.let { 
                ... 
                executor.execute { 
                    ... 
                    sendMessage(result) 
                } 
            } 
        } 

        override fun onStatusChanged(p0: String?, p1: Int, p2: Bundle?)
        {} 
        override fun onProviderEnabled(p0: String?) {} 
        override fun onProviderDisabled(p0: String?) {} 
      } 
      ... 
      private fun updateNote() { 
        if (note == null) { 
            ... 
        } else { 
            ... 
            executor.execute { 
                ... 
                sendMessage(result) 
            } 
        } 
      } 
     ... 
     private fun sendMessage(result: Boolean) { 
        val msg = handler?.obtainMessage() 
        if (result) { 
            msg?.arg1 = 1 
        } else { 
            msg?.arg1 = 0 
        } 
        handler?.sendMessage(msg) 
     } 
     ... 
    } 
```

注意处理程序的实例化和`sendMessage()`方法。我们使用`Handler`类的`obtainMessage()`方法获取了`Message`实例。作为消息参数，我们传递了一个整数数据类型。根据它的值，我们将更新指示器的颜色。

# AsyncTask

你可能已经注意到，我们已经在我们的应用程序中使用了`AsyncTask`类。现在，我们将进一步运用它--我们将在执行器上运行它。为什么我们要这样做呢？

首先，默认情况下，所有的`AsyncTasks`都是按顺序在 Android 中执行的。要并行执行它，我们需要在执行器上执行它。

等等！现在，当我们并行执行任务时，想象一下你执行了一些任务。比如说我们从两个开始。这很好。它们将执行它们的操作并在完成时向我们报告。然后，想象一下我们同时运行了四个任务。它们也会工作，在大多数情况下，如果它们执行的操作不太繁重。然而，在某些时候，我们同时运行了五十个`AsyncTasks`。

然后，你的应用程序变慢了！一切都会变慢，因为对任务的执行没有控制。我们必须管理任务，以保持性能。所以，让我们来做吧！我们将继续更新到目前为止更新的同一个类。按照以下方式更改你的`NoteActivity`：

```kt
    class NoteActivity : ItemActivity() { 
      ... 
      private val threadPoolExecutor = ThreadPoolExecutor( 
            3, 3, 1, TimeUnit.SECONDS, LinkedBlockingQueue<Runnable>() 
    ) 

    private class TryAsync(val identifier: String) : AsyncTask<Unit,
    Int, Unit>() { 
        private val tag = "TryAsync" 

        override fun onPreExecute() { 
            Log.i(tag, "onPreExecute [ $identifier ]") 
            super.onPreExecute() 
      } 

      override fun doInBackground(vararg p0: Unit?): Unit { 
         Log.i(tag, "doInBackground [ $identifier ][ START ]") 
         Thread.sleep(5000) 
         Log.i(tag, "doInBackground [ $identifier ][ END ]") 
         return Unit 
       } 

       override fun onCancelled(result: Unit?) { 
         Log.i(tag, "onCancelled [ $identifier ][ END ]") 
         super.onCancelled(result) 
        } 

       override fun onProgressUpdate(vararg values: Int?) { 
         val progress = values.first() 
         progress?.let { 
           Log.i(tag, "onProgressUpdate [ $identifier ][ $progress ]") 
         } 
          super.onProgressUpdate(*values) 
        } 

        override fun onPostExecute(result: Unit?) { 
          Log.i(tag, "onPostExecute [ $identifier ]") 
          super.onPostExecute(result) 
        } 
      } 
      ... 
      private val textWatcher = object : TextWatcher { 
        override fun afterTextChanged(p0: Editable?) { 
            ... 
        } 

      override fun beforeTextChanged(p0: CharSequence?, p1: Int, p2:
      Int, p3: Int) {} 

      override fun onTextChanged(p0: CharSequence?, p1: Int, p2: Int,
      p3: Int) { 
            p0?.let {  
                tryAsync(p0.toString())  
            } 
        } 
     } 
     ... 
     private fun tryAsync(identifier: String) { 
        val tryAsync = TryAsync(identifier) 
        tryAsync.executeOnExecutor(threadPoolExecutor) 
     } 
    } 
```

由于这实际上不是我们将在 Journaler 应用程序中保留的内容，请不要提交此代码。如果你愿意，可以将其创建为一个单独的分支。我们创建了一个`ThreadPoolExecutor`的新实例。构造函数接受几个参数，如下所示：

+   `corePoolSize`：这代表了池中保持的最小线程数。

+   `maximumPoolSize`：这代表了池中允许的最大线程数。

+   `keepAliveTime`：如果线程数大于核心数，非核心线程将等待新任务，如果在这个参数定义的时间内没有得到新任务，它们将终止。

+   `Unit`：这代表了`keepAliveTime`的时间单位。

+   `WorkQueue`：这代表了将用于保存任务的队列实例。

+   我们将在这个执行器上运行我们的任务。`AsyncTask`具体化将记录其生命周期中的所有事件。在`main`方法中，我们将等待 5 秒。运行应用程序，尝试添加一个标题为`Android`的新笔记。观察你的 Logcat 输出：

```kt
08-04 14:56:59.283 21953-21953 ... I/TryAsync: onPreExecute [ A ] 
08-04 14:56:59.284 21953-23233 ... I/TryAsync: doInBackground [ A ][ START ] 
08-04 14:57:00.202 21953-21953 ... I/TryAsync: onPreExecute [ An ] 
08-04 14:57:00.204 21953-23250 ... I/TryAsync: doInBackground [ An ][ START ] 
08-04 14:57:00.783 21953-21953 ... I/TryAsync: onPreExecute [ And ] 
08-04 14:57:00.784 21953-23281 ... I/TryAsync: doInBackground [ And ][ START ] 
08-04 14:57:01.001 21953-21953 ... I/TryAsync: onPreExecute [ Andr ] 
08-04 14:57:01.669 21953-21953 ... I/TryAsync: onPreExecute [ Andro ] 
08-04 14:57:01.934 21953-21953 ... I/TryAsync: onPreExecute [ Androi ] 
08-04 14:57:02.314 21953-2195 ... I/TryAsync: onPreExecute [ Android ] 
08-04 14:57:04.285 21953-23233 ... I/TryAsync: doInBackground [ A ][ END ] 
08-04 14:57:04.286 21953-23233 ... I/TryAsync: doInBackground [ Andr ][ START ] 
08-04 14:57:04.286 21953-21953 ... I/TryAsync: onPostExecute [ A ] 
08-04 14:57:05.204 21953-23250 ... I/TryAsync: doInBackground [ An ][ END ] 
08-04 14:57:05.204 21953-21953 ... I/TryAsync: onPostExecute [ An ] 
08-04 14:57:05.205 21953-23250 ... I/TryAsync: doInBackground [ Andro ][ START ] 
08-04 14:57:05.784 21953-23281 ... I/TryAsync: doInBackground [ And ][ END ] 
08-04 14:57:05.785 21953-23281 ... I/TryAsync: doInBackground [ Androi ][ START ] 
08-04 14:57:05.786 21953-21953 ... I/TryAsync: onPostExecute [ And ] 
08-04 14:57:09.286 21953-23233 ... I/TryAsync: doInBackground [ Andr ][ END ] 
08-04 14:57:09.287 21953-21953 ... I/TryAsync: onPostExecute [ Andr ] 
08-04 14:57:09.287 21953-23233 ... I/TryAsync: doInBackground [ Android ][ START ] 
08-04 14:57:10.205 21953-23250 ... I/TryAsync: doInBackground [ Andro ][ END ] 
08-04 14:57:10.206 21953-21953 ... I/TryAsync: onPostExecute [ Andro ] 
08-04 14:57:10.786 21953-23281 ... I/TryAsync: doInBackground [ Androi ][ END ] 
08-04 14:57:10.787 21953-2195 ... I/TryAsync: onPostExecute [ Androi ] 
08-04 14:57:14.288 21953-23233 ... I/TryAsync: doInBackground [ Android ][ END ] 
08-04 14:57:14.290 21953-2195 ... I/TryAsync: onPostExecute [ Android ] 
```

让我们通过我们在任务中执行的方法来过滤日志。首先让我们看一下`onPreExecute`方法的过滤器：

```kt
08-04 14:56:59.283 21953-21953 ... I/TryAsync: onPreExecute [ A ] 
08-04 14:57:00.202 21953-21953 ... I/TryAsync: onPreExecute [ An ] 
08-04 14:57:00.783 21953-21953 ... I/TryAsync: onPreExecute [ And ] 
08-04 14:57:01.001 21953-21953 ... I/TryAsync: onPreExecute [ Andr ] 
08-04 14:57:01.669 21953-21953 ... I/TryAsync: onPreExecute [ Andro ] 
08-04 14:57:01.934 21953-21953 ... I/TryAsync: onPreExecute [ Androi ] 
08-04 14:57:02.314 21953-21953 ... I/TryAsync: onPreExecute [ Android ] 
```

对每个方法都做同样的事情，并关注方法执行的时间。为了给你的代码更多的挑战，将`doInBackground()`方法的实现改为做一些更严肃和密集的工作。然后，通过输入一个更长的标题来触发更多的任务，例如整个句子。过滤和分析你的日志。

# 理解 Android Looper

让我们解释一下`Looper`类。我们在之前的例子中用过它，但我们没有详细解释过它。

`Looper`代表了一个用于在队列中执行`messages`或`runnable`实例的类。普通线程没有像`Looper`类那样的队列。

我们在哪里可以使用`Looper`类？对于执行多个`messages`或`runnable`实例，需要`Looper`！一个使用的例子可以是在添加新任务到队列的同时，任务处理操作正在运行。

# 准备 Looper

要使用`Looper`类，我们必须首先调用`prepare()`方法。当`Looper`准备好后，我们可以使用`loop()`方法。这个方法用于在当前线程中创建一个`message`循环。我们将给你一个简短的例子：

```kt
    class LooperHandler : Handler() { 
      override fun handleMessage(message: Message) { 
            ... 
      } 
    } 

    class LooperThread : Thread() { 
      var handler: Handler? = null 

      override fun run() { 
         Looper.prepare() 
         handler = LooperHandler() 
         Looper.loop() 
      } 
    } 
```

在这个例子中，我们演示了编程`Looper`类的基本步骤。不要忘记`prepare()`你的`Looper`类，否则你会得到一个异常，你的应用程序可能会崩溃！

# 延迟执行

本章还有一件重要的事情要向你展示。我们将向你展示在 Android 中的延迟执行。我们将给你一些延迟操作应用到我们的 UI 的例子。打开你的`ItemsFragment`并做出以下更改：

```kt
     class ItemsFragment : BaseFragment() { 
      ... 
       override fun onResume() { 
         super.onResume() 
         ... 
         val items = view?.findViewById<ListView>(R.id.items) 
         items?.let { 
            items.postDelayed({ 
              if (!activity.isFinishing) { 
                items.setBackgroundColor(R.color.grey_text_middle) 
              } 
            }, 3000) 
         } 
      } 
       ... 
     } 
```

三秒后，如果我们不关闭这个屏幕，背景颜色将变成稍微深一点的灰色。运行你的应用程序，亲自看看。现在，让我们用另一种方式做同样的事情：

```kt
     class ItemsFragment : BaseFragment() { 
      ... 
      override fun onResume() { 
        super.onResume() 
        ... 
        val items = view?.findViewById<ListView>(R.id.items) 
        items?.let { 
            Handler().postDelayed({ 
                if (!activity.isFinishing) { 
                    items.setBackgroundColor(R.color.grey_text_middle) 
                } 
            }, 3000) 
         } 
        } 
       } 
       ...
     }
```

这一次，我们使用了`Handler`类来执行延迟修改。

# 总结

在本章中，我们向您介绍了 Android 并发性。我们为每个部分进行了解释，并为您提供了示例。在深入了解 Android 服务之前，这是一个很好的介绍。Android 服务是 Android 提供的最强大的并发特性，正如您将看到的，它可以被用作应用程序的大脑。


# 第十章：Android 服务

在上一章中，我们开始使用 Android 中的并发机制。我们取得了很大的进展。然而，我们对 Android 并发机制的旅程还没有结束。我们必须介绍 Android 框架中可能是最重要的部分--Android 服务。在本章中，我们将解释服务是什么，何时以及如何使用它们。

在本章中，我们将涵盖以下主题：

+   服务分类

+   Android 服务的基础知识

+   定义主要应用程序服务

+   定义意图服务

# 服务分类

在我们定义 Android 服务分类并深入研究每种类型之前，我们必须回答 Android 服务到底是什么。嗯，**Android 服务**是 Android 框架提供的一种机制，通过它我们可以将长时间运行的任务移至后台。Android 服务提供了一些很好的附加功能，可以使开发人员的工作更加灵活和简单。为了解释它如何使我们的开发更容易，我们将通过扩展我们的 Journaler 应用程序来创建一个服务。

Android 服务是一个没有任何 UI 的应用程序组件。它可以被任何 Android 应用程序组件启动，并在需要时继续运行，即使我们离开我们的应用程序或杀死它。

Android 服务有三种主要类型：

+   前台

+   背景

+   绑定

# 前台 Android 服务

前台服务执行的任务对最终用户是可见的。这些服务必须显示状态栏图标。即使没有与应用程序的交互，它们也会继续运行。

# 后台 Android 服务

与前台服务不同，后台服务执行的任务不会被最终用户注意到。例如，我们将与后端实例进行同步。用户不需要知道我们的进度。我们决定不去打扰用户。一切都将在我们应用程序的后台默默执行。

# 绑定 Android 服务

我们的应用程序组件可以绑定到一个服务并触发不同的任务来执行。在 Android 中与服务交互非常简单。只要有至少一个这样的组件，服务就会继续运行。当没有组件绑定到服务时，服务就会被销毁。

可以创建一个在后台运行并具有绑定能力的后台服务。

# Android 服务基础知识

要定义 Android 服务，您必须扩展`Service`类。我们必须重写以下一些方法，以便服务能够正常运行：

+   `onStartCommand()`: 当`startService()`方法被某个 Android 组件触发时执行此方法。方法执行后，Android 服务就会启动并可以在后台无限期运行。要停止这个服务，必须执行`stopService()`方法，它与`startService()`方法的功能相反。

+   `onBind()`: 要从另一个 Android 组件绑定到服务，请使用`bindService()`方法。绑定后，将执行`onBind()`方法。在此方法的服务实现中，您必须提供一个接口，客户端通过返回一个`Ibinder`类实例与服务通信。实现此方法是不可选的，但如果您不打算绑定到服务，只需返回`null`即可。

+   `onCreate()`: 当服务被创建时执行此方法。如果服务已经在运行，则不会执行此方法。

+   `onDestroy()`: 当服务被销毁时执行此方法。重写此方法并在此处执行所有清理任务。

+   `onUnbind()`: 当我们从服务解绑时执行此方法。

# 声明您的服务

要声明您的服务，您需要将其类添加到 Android 清单中。以下代码片段解释了 Android 清单中服务定义应该是什么样子的：

```kt
    <manifest xmlns:android=
     "http://schemas.android.com/apk/res/android"   
      package="com.journaler"> 
      ... 
      <application ... > 
        <service 
          android:name=".service.MainService" 
          android:exported="false" /> 
          ... 

      </application> 
     </manifest>

```

正如你所看到的，我们定义了扩展`Service`类的`MainService`类，并且它位于`service`包下。导出标志设置为`false`，这意味着`service`将在与我们的应用程序相同的进程中运行。要在一个单独的进程中运行你的`service`，将这个标志设置为`true`。

重要的是要注意，`Service`类不是你唯一可以扩展的类。`IntentService`类也是可用的。那么，当我们扩展它时，我们会得到什么？`IntentService`代表从`Service`类派生的类。`IntentService`使用工作线程逐个处理请求。我们必须实现`onHandleIntent()`方法来实现这个目的。当`IntentService`类被扩展时，它看起来像这样：

```kt
     public class MainIntentService extends IntentService { 
       /** 
       * A constructor is mandatory! 
       */ 
       public MainIntentService() { 
         super("MainIntentService"); 
       } 

       /** 
       * All important work is performed here. 
       */ 
       @Override 
       protected void onHandleIntent(Intent intent) { 
         // Your implementation for handling received intents. 

       } 
     } 
```

让我们回到扩展`Service`类并专注于它。我们将重写`onStartCommand()`方法，使其看起来像这样：

```kt
    override fun onStartCommand(intent: Intent?, flags: Int, startId:  
    Int): Int { 

      return Service.START_STICKY 
    }
```

那么，`START_STICKY`返回的结果是什么意思？如果我们的服务被系统杀死，或者我们杀死了服务所属的应用程序，它将重新启动。相反的是`START_NOT_STICKY`；在这种情况下，服务将不会被重新创建和重新启动。

# 启动服务

要启动服务，我们需要定义代表它的意图。这是服务可以启动的一个例子：

```kt
    val startServiceIntent = Intent(ctx, MainService::class.java) 
    ctx.startService(startServiceIntent) 
```

这里，`ctx`代表 Android `Context`类的任何有效实例。

# 停止服务

要停止服务，执行 Android `Context`类的`stopService()`方法，就像这样：

```kt
     val stopServiceIntent = Intent(ctx, MainService::class.java)
     ctx.stopService(startServiceIntent) 
```

# 绑定到 Android 服务

**绑定服务**是允许 Android 组件绑定到它的服务。要执行绑定，我们必须调用`bindService()`方法。当你想要从活动或其他 Android 组件与服务交互时，服务绑定是必要的。为了使绑定工作，你必须实现`onBind()`方法并返回一个`IBinder`实例。如果没有人感兴趣了，所有人都解绑了，Android 就会销毁服务。对于这种类型的服务，你不需要执行停止例程。

# 停止服务

我们已经提到`stopService`将停止我们的服务。无论如何，我们可以通过在我们的服务实现中调用`stopSelf()`来实现相同的效果。

# 服务生命周期

我们涵盖并解释了在 Android 服务的生命周期中执行的所有重要方法。服务像所有其他 Android 组件一样有自己的生命周期。到目前为止我们提到的一切都在下面的截图中表示出来：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/38a59665-0d7e-433a-8e7a-5188c64ad0cd.png)

现在，我们对 Android 服务有了基本的了解，我们将创建我们自己的服务并扩展 Journaler 应用程序。这个服务将在后面的章节中被重复扩展更多的代码。所以，请注意每一行，因为它可能是至关重要的。

# 定义主应用程序服务

正如你已经知道的，我们的应用程序处理笔记和待办事项。当前的应用程序实现将我们的数据保存在 SQLite 数据库中。这些数据将与运行在某个远程服务器上的后端实例进行同步。所有与同步相关的操作将在我们应用程序的后台默默执行。所有的责任将交给我们将要定义的服务。创建一个名为`service`的新包和一个名为`MainService`的新类，它将扩展 Android `service`类。确保你的实现看起来像这样：

```kt
    class MainService : Service(), DataSynchronization { 

      private val tag = "Main service" 
      private var binder = getServiceBinder() 
      private var executor = TaskExecutor.getInstance(1) 

      override fun onCreate() { 
        super.onCreate() 
        Log.v(tag, "[ ON CREATE ]") 
      } 

      override fun onStartCommand(intent: Intent?, flags: Int, startId:
      Int): Int { 
        Log.v(tag, "[ ON START COMMAND ]") 
        synchronize() 
        return Service.START_STICKY 
      } 

      override fun onBind(p0: Intent?): IBinder { 
        Log.v(tag, "[ ON BIND ]") 
        return binder 
      } 

      override fun onUnbind(intent: Intent?): Boolean { 
        val result = super.onUnbind(intent) 
        Log.v(tag, "[ ON UNBIND ]") 
        return result 
      } 

      override fun onDestroy() { 
        synchronize() 
        super.onDestroy() 
        Log.v(tag, "[ ON DESTROY ]") 
      } 

      override fun onLowMemory() { 
        super.onLowMemory() 
        Log.w(tag, "[ ON LOW MEMORY ]") 
      } 

      override fun synchronize() { 
        executor.execute { 
            Log.i(tag, "Synchronizing data [ START ]") 
            // For now we will only simulate this operation! 
            Thread.sleep(3000) 
            Log.i(tag, "Synchronizing data [ END ]") 
        } 
      } 

      private fun getServiceBinder(): MainServiceBinder = 
      MainServiceBinder() 

      inner class MainServiceBinder : Binder() { 
        fun getService(): MainService = this@MainService 
      } 
    }
```

让我们解释一下我们的主要服务。正如你们已经知道的，我们将扩展 Android 的`Service`类以获得所有的服务功能。我们还实现了`DataSynchronization`接口，它将描述我们服务的主要功能，即同步。请参考以下代码：

```kt
    package com.journaler.service 
    interface DataSynchronization { 

     fun synchronize() 
    }
```

所以，我们定义了`synchronize()`方法的实现，它实际上将模拟真正的同步。稍后，我们将更新这段代码以执行真正的后端通信。

所有重要的生命周期方法都被重写。注意`bind()`方法！此方法将通过调用`getServiceBinder()`方法返回一个由`MainServiceBinder`类生成的绑定器实例。由于`MainServiceBinder`类，我们将向最终用户公开我们的`service`实例，最终用户将能够在需要时触发同步机制。

同步不仅仅是由最终用户触发的，还会被服务自动触发。当服务启动和销毁时，我们会触发同步。

对我们来说，`MainService`的启动和停止是下一个重要的点。打开代表您的应用程序的`Journaler`类，并应用此更新：

```kt
     class Journaler : Application() { 

       companion object { 
         val tag = "Journaler" 
         var ctx: Context? = null 
       } 

       override fun onCreate() { 
         super.onCreate() 
         ctx = applicationContext 
         Log.v(tag, "[ ON CREATE ]") 
         startService() 
       } 

       override fun onLowMemory() { 
         super.onLowMemory() 
         Log.w(tag, "[ ON LOW MEMORY ]") 
         // If we get low on memory we will stop service if running. 
         stopService() 
       } 

       override fun onTrimMemory(level: Int) { 
         super.onTrimMemory(level) 
         Log.d(tag, "[ ON TRIM MEMORY ]: $level") 
       } 

       private fun startService() { 
         val serviceIntent = Intent(this, MainService::class.java) 
         startService(serviceIntent) 
       } 

       private fun stopService() { 
        val serviceIntent = Intent(this, MainService::class.java) 
        stopService(serviceIntent) 
       } 

     } 
```

当 Journaler 应用程序被创建时，`MainService`将被启动。我们还将添加一个小的优化。如果我们的应用程序内存不足，我们将停止我们的`MainService`类。由于服务是粘性启动的，如果我们明确杀死我们的应用程序，服务将重新启动。

到目前为止，我们已经涵盖了服务的启动和停止以及其实现。您可能还记得我们的模拟，在我们的应用程序抽屉底部，我们计划放置一个额外的项目。我们计划放置同步按钮。触发此按钮将与后端进行同步。

我们将添加该菜单项并将其与我们的服务连接起来。首先让我们做一些准备工作。打开`NavigationDrawerItem`类并按以下方式更新它：

```kt
    data class NavigationDrawerItem( 
      val title: String, 
      val onClick: Runnable, 
      var enabled: Boolean = true 
    ) 
```

我们引入了`enabled`参数。这样，如果需要，我们的应用程序抽屉中的一些项目可以被禁用。我们的同步按钮将默认禁用，并在绑定到`main`服务时启用。这些更改也必须影响`NavigationDrawerAdapter`。请参考以下代码：

```kt
    class NavigationDrawerAdapter( 
      val ctx: Context, 
      val items: List<NavigationDrawerItem> 
      ) : BaseAdapter() { 

        private val tag = "Nav. drw. adptr." 

        override fun getView(position: Int, v: View?, group: 
        ViewGroup?): View { 
          ... 
          val item = items[position] 
          val title = view.findViewById<Button>(R.id.drawer_item) 
          ... 
          title.setOnClickListener { 
            if (item.enabled) { 
                item.onClick.run() 
            } else { 
                Log.w(tag, "Item is disabled: $item") 
            } 
          } 

          return view 
       } 
        ... 
    }
```

最后，我们将更新我们的`MainActivity`类如下，以便同步按钮可以触发同步：

```kt
    class MainActivity : BaseActivity() { 
      ... 
      private var service: MainService? = null 

      private val synchronize: NavigationDrawerItem by lazy { 
        NavigationDrawerItem( 
          getString(R.string.synchronize), 
          Runnable { service?.synchronize() }, 
          false 
        ) 
     } 

     private val serviceConnection = object : ServiceConnection { 
        override fun onServiceDisconnected(p0: ComponentName?) { 
            service = null 
            synchronize.enabled = false 
        } 

        override fun onServiceConnected(p0: ComponentName?, binder: 
        IBinder?) { 
          if (binder is MainService.MainServiceBinder) { 
            service = binder.getService() 
            service?.let { 
              synchronize.enabled = true 
            } 
           } 
        } 
     } 

      override fun onCreate(savedInstanceState: Bundle?) { 
        super.onCreate(savedInstanceState) 
        ... 
        val menuItems = mutableListOf<NavigationDrawerItem>() 
        ... 
        menuItems.add(synchronize) 
        ... 
      } 

      override fun onResume() { 
        super.onResume() 
        val intent = Intent(this, MainService::class.java) 
        bindService(intent, serviceConnection, 
        android.content.Context.BIND_AUTO_CREATE) 
     } 

     override fun onPause() { 
        super.onPause() 
        unbindService(serviceConnection) 
     } 

     ... 
    } 
```

我们将根据我们的主活动状态是否活动来绑定或解绑`main`服务。为了执行绑定，我们需要`ServiceConnection`实现，因为它将根据绑定状态启用或禁用同步按钮。此外，我们将根据绑定状态维护`main`服务实例。同步按钮将访问`service`实例，并在点击时触发`synchronize()`方法。

# 定义`intent`服务

我们的`main`服务正在运行并且责任已定义。现在，我们将通过引入另一个服务来对我们的应用程序进行更多改进。这一次，我们将定义`intent`服务。`intent`服务将接管数据库 CRUD 操作的执行责任。基本上，我们将定义我们的`intent`服务并对我们已有的代码进行重构。

首先，我们将在`service`包内创建一个名为`DatabaseService`的新类。在我们放置整个实现之前，我们将在 Android 清单中注册它如下：

```kt
    <manifest xmlns:android=
      "http://schemas.android.com/apk/res/android" 
       package="com.journaler"> 
       ... 
      <application ... > 
      <service 
        android:name=".service.MainService" 
        android:exported="false" /> 

      <service 
        android:name=".service.DatabaseService" 
        android:exported="false" /> 
        ... 
      </application> 
    </manifest> 

    Define DatabaseService like this: 
    class DatabaseService :
     IntentService("DatabaseService") { 

       companion object { 
         val EXTRA_ENTRY = "entry" 
         val EXTRA_OPERATION = "operation" 
       } 

       private val tag = "Database service" 

       override fun onCreate() { 
         super.onCreate() 
         Log.v(tag, "[ ON CREATE ]") 
       } 

       override fun onLowMemory() { 
         super.onLowMemory() 
         Log.w(tag, "[ ON LOW MEMORY ]") 
       } 

       override fun onDestroy() { 
         super.onDestroy() 
         Log.v(tag, "[ ON DESTROY ]") 
       } 

       override fun onHandleIntent(p0: Intent?) { 
         p0?.let { 
            val note = p0.getParcelableExtra<Note>(EXTRA_ENTRY) 
            note?.let { 
               val operation = p0.getIntExtra(EXTRA_OPERATION, -1) 
               when (operation) { 
                 MODE.CREATE.mode -> { 
                   val result = Db.insert(note) 
                   if (result) { 
                      Log.i(tag, "Note inserted.") 
                   } else { 
                      Log.e(tag, "Note not inserted.") 
                      } 
                   } 
                   MODE.EDIT.mode -> { 
                     val result = Db.update(note) 
                     if (result) { 
                       Log.i(tag, "Note updated.") 
                     } else { 
                       Log.e(tag, "Note not updated.") 
                      } 
                    } 
                    else -> { 
                        Log.w(tag, "Unknown mode [ $operation ]") 
                    } 

                  } 

                } 

             } 

         } 

     } 
```

服务将接收意图，获取操作，并从中获取实例。根据操作，将触发适当的 CRUD 操作。为了将`Note`实例传递给`Intent`，我们必须实现`Parcelable`，以便数据传递效率高。例如，与`Serializable`相比，`Parcelable`要快得多。为此目的，代码已经进行了大量优化。我们将执行显式序列化，而不使用反射。打开您的`Note`类并按以下方式更新它：

```kt
    package com.journaler.model 
    import android.location.Location 
    import android.os.Parcel 
    import android.os.Parcelable 

    class Note( 
      title: String, 
      message: String, 
      location: Location 
    ) : Entry( 
      title, 
      message, 
      location 
    ), Parcelable { 

      override var id = 0L 

      constructor(parcel: Parcel) : this( 
        parcel.readString(), 
        parcel.readString(), 
        parcel.readParcelable(Location::class.java.classLoader) 
      ) { 
         id = parcel.readLong() 
        } 

       override fun writeToParcel(parcel: Parcel, flags: Int) { 
         parcel.writeString(title) 
         parcel.writeString(message) 
         parcel.writeParcelable(location, 0) 
         parcel.writeLong(id) 
       } 

       override fun describeContents(): Int { 
         return 0 
       } 

       companion object CREATOR : Parcelable.Creator<Note> { 
         override fun createFromParcel(parcel: Parcel): Note { 
            return Note(parcel) 
        } 

         override fun newArray(size: Int): Array<Note?> { 
            return arrayOfNulls(size) 
        } 
      } 

    } 
```

当通过`intent`传递到`DatabaseService`时，`Note`类将被高效地序列化和反序列化。

最后一块拼图是更改当前执行 CRUD 操作的代码。我们将创建`intent`并将其发送，以便我们的服务为我们处理其余工作。打开`NoteActivity`类并按以下方式更新代码：

```kt
    class NoteActivity : ItemActivity() { 
      ... 
      private val locationListener = object : LocationListener { 
        override fun onLocationChanged(p0: Location?) { 
          p0?.let { 
            LocationProvider.unsubscribe(this) 
            location = p0 
            val title = getNoteTitle() 
            val content = getNoteContent() 
            note = Note(title, content, p0) 

            // Switching to intent service. 
            val dbIntent = Intent(this@NoteActivity, 
            DatabaseService::class.java) 
            dbIntent.putExtra(DatabaseService.EXTRA_ENTRY, note) 
            dbIntent.putExtra(DatabaseService.EXTRA_OPERATION, 
            MODE.CREATE.mode) 
            startService(dbIntent) 
            sendMessage(true) 
          } 
      } 

     override fun onStatusChanged(p0: String?, p1: Int, p2: Bundle?) {} 
     override fun onProviderEnabled(p0: String?) {} 
     override fun onProviderDisabled(p0: String?) {} 
   } 
    ... 
    private fun updateNote() { 
      if (note == null) { 
        if (!TextUtils.isEmpty(getNoteTitle()) && 
        !TextUtils.isEmpty(getNoteContent())) { 
           LocationProvider.subscribe(locationListener) 
        } 
        } else { 
            note?.title = getNoteTitle() 
            note?.message = getNoteContent() 

            // Switching to intent service. 
            val dbIntent = Intent(this@NoteActivity, 
            DatabaseService::class.java) 
            dbIntent.putExtra(DatabaseService.EXTRA_ENTRY, note) 
            dbIntent.putExtra(DatabaseService.EXTRA_OPERATION,
            MODE.EDIT.mode) 
            startService(dbIntent) 
            sendMessage(true) 
        } 
      } 
      ... 
    } 
```

正如你所看到的，改变真的很简单。构建你的应用程序并运行它。当你创建或更新你的`Note`类时，你会注意到我们执行的数据库操作的日志。此外，你还会注意到`DatabaseService`的生命周期方法被记录下来。

# 总结

恭喜！你掌握了 Android 服务并显著改进了应用程序！在本章中，我们解释了什么是 Android 服务。我们还解释了每种类型的 Android 服务，并举例说明了它们的用途。现在，当你完成这些实现时，我们鼓励你至少考虑一个可以接管应用程序的某个现有部分或引入全新内容的服务。玩转这些服务，并尝试思考它们能给你带来的好处。
